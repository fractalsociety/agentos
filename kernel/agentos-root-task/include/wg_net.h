/*
 * wg_net.h — WireGuard Overlay Network Protection Domain
 *
 * Provides an encrypted, peer-to-peer overlay network for agent-to-agent
 * communication using WireGuard's Noise_IKpsk2 handshake protocol backed
 * by Curve25519 ECDH and ChaCha20-Poly1305 AEAD.
 *
 * Architecture:
 *   - Up to WG_MAX_PEERS (16) peers in a static peer table
 *   - Each peer is identified by a uint8_t peer_id (0..WG_MAX_PEERS-1)
 *   - Peer public keys are Curve25519 (32 bytes each)
 *   - Optional preshared keys per peer for post-quantum resistance
 *   - Keepalive timer fires every 25 seconds (per WireGuard spec §6.1)
 *   - Encrypted payloads forwarded via net_server's OP_NET_VNIC_SEND
 *
 * Shared memory:
 *   wg_staging (mapped at setvar_vaddr): staging region for key material
 *   and send/receive packet buffers. Layout:
 *     [0x000000 .. 0x00001F]  local private key (32 bytes, write-once)
 *     [0x000020 .. 0x00003F]  local public key  (32 bytes, read-only after init)
 *     [0x001000 .. 0x001FFF]  peer pubkey staging (OP_WG_ADD_PEER uses this)
 *     [0x002000 .. 0x00FFFF]  TX packet staging  (OP_WG_SEND plaintext input)
 *     [0x010000 .. 0x01FFFF]  RX packet staging  (OP_WG_RECV decrypted output)
 *
 * Crypto status:
 *   Curve25519, RFC 8439 ChaCha20-Poly1305, and the canonical WireGuard
 *   Noise_IKpsk2 transcript/KDF/session derivation are implemented in the
 *   freestanding crypto library. UDP/IP encapsulation, rekey timers, cookie
 *   replies, and roaming remain transport integration work.
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "wireguard_counter.h"
#include "wireguard_noise.h"

/* ── Limits ──────────────────────────────────────────────────────────────── */
#define WG_MAX_PEERS        16u   /* maximum simultaneous WireGuard peers */
#define WG_KEY_LEN          32u   /* Curve25519 key length in bytes */

/* Shared staging geometry. NetServer receives only the page-aligned packet
 * view beginning at WG_STAGING_TX_OFF; it never maps the key pages below it. */
#define WG_STAGING_VA             0x08000000UL
#define WG_STAGING_SIZE           0x00100000u
#define WG_STAGING_PRIVKEY_OFF    0x000000u
#define WG_STAGING_PUBKEY_OFF     0x000020u
#define WG_STAGING_PEER_KEY_OFF   0x001000u
#define WG_STAGING_TX_OFF         0x002000u
#define WG_STAGING_RX_OFF         0x010000u
#define WG_STAGING_TX_MAX         0x00E000u
#define WG_STAGING_RX_MAX         0x00E000u
#define WG_STAGING_INGRESS_OFF    0x011000u

/* ── Keepalive interval (WireGuard spec §6.1) ────────────────────────────── */
#define WG_KEEPALIVE_SECS   25u   /* send keepalive if no traffic for 25s */

/* ── IPC Opcodes ─────────────────────────────────────────────────────────── */

/*
 * OP_WG_ADD_PEER (0xD0) — register a new WireGuard peer
 *   MR1 = peer_id         (uint8_t, 0..WG_MAX_PEERS-1)
 *   MR2 = pubkey_offset   (byte offset into wg_staging for the 32-byte public key)
 *   MR3 = endpoint_ip_be  (IPv4 endpoint address, network byte order)
 *   MR4 = endpoint_port   (UDP port, host byte order)
 *   MR5 = allowed_ip_be   (allowed-IP network address, network byte order)
 *   MR6 = allowed_mask    (subnet mask in host byte order, e.g. 0xFFFFFF00 for /24)
 *   Reply:
 *   MR0 = result (WG_OK or WG_ERR_*)
 */
#define OP_WG_ADD_PEER      0xD0u

/*
 * OP_WG_REMOVE_PEER (0xD1) — deregister a peer and clear its keys
 *   MR1 = peer_id
 *   Reply:
 *   MR0 = result
 */
#define OP_WG_REMOVE_PEER   0xD1u

/*
 * OP_WG_SEND (0xD2) — encrypt and transmit a packet to a peer
 *   MR1 = peer_id       (identifies which peer's session keys to use)
 *   MR2 = data_offset   (byte offset into wg_staging TX region for plaintext)
 *   MR3 = data_len      (plaintext length in bytes; max 65535)
 *   Reply:
 *   MR0 = result
 *   MR1 = bytes_sent    (ciphertext length after encryption)
 *
 *   The wg_net PD encrypts the payload at wg_staging[data_offset..data_offset+data_len]
 *   using ChaCha20-Poly1305, prepends a WireGuard transport
 *   header, and forwards to net_server via OP_NET_VNIC_SEND on the wg_net vNIC.
 */
#define OP_WG_SEND          0xD2u

/*
 * OP_WG_RECV (0xD3) — poll for a received, decrypted packet from a peer
 *   MR1 = peer_id       (0xFF = receive from any peer)
 *   Reply:
 *   MR0 = result
 *   MR1 = src_peer_id   (actual peer the packet came from)
 *   MR2 = data_offset   (byte offset into wg_staging RX region for plaintext)
 *   MR3 = data_len      (plaintext length; 0 if no packet pending)
 *
 *   Non-blocking: returns WG_OK with data_len=0 if no packet is available.
 *   The caller must read decrypted data from wg_staging before the next call.
 */
#define OP_WG_RECV          0xD3u

/*
 * OP_WG_STATUS (0xD4) — query WireGuard overlay status
 *   Reply:
 *   MR0 = result (WG_OK)
 *   MR1 = active_peer_count
 *   MR2 = total_tx_bytes (lower 32 bits)
 *   MR3 = total_rx_bytes (lower 32 bits)
 *   MR4 = last_handshake_secs (seconds since epoch of most recent handshake, or 0)
 */
#define OP_WG_STATUS        0xD4u

/*
 * OP_WG_SET_PRIVKEY (0xD5) — set the local WireGuard private key
 *   MR1 = key_offset    (byte offset into wg_staging; 32 bytes of Curve25519 key)
 *   Reply:
 *   MR0 = result (WG_OK or WG_ERR_CRYPTO if key is degenerate)
 *
 *   After setting the private key, the PD derives the public key via Curve25519
 *   scalar multiplication and stores it in
 *   wg_staging[0x20..0x3F] for the caller to read.
 *   This opcode must be called before any OP_WG_SEND will succeed.
 */
#define OP_WG_SET_PRIVKEY   0xD5u

/*
 * OP_WG_HEALTH (0xD6) — liveness check
 *   Reply:
 *   MR0 = WG_OK (0)
 *   MR1 = active_peer_count
 *   MR2 = 1 if private key is set, 0 otherwise
 *   MR3 = authenticated_session_count
 */
#define OP_WG_HEALTH        0xD6u

/*
 * OP_WG_HANDSHAKE_START (0xD7) — create a Noise initiation for one peer
 *   MR1 = peer_id
 *   MR2 = ephemeral_private_offset (absolute wg_staging offset, 32 bytes)
 *   MR3 = TAI64N timestamp_offset   (absolute wg_staging offset, 12 bytes)
 *   MR4 = sender_index              (non-zero local receiver index)
 *   Reply: MR0 = result; MR1 = TX offset; MR2 = message length (148)
 */
#define OP_WG_HANDSHAKE_START 0xD7u

/*
 * OP_WG_INGEST (0xD8) — authenticate an incoming WireGuard packet
 *   MR1 = packet_offset (absolute offset in the RX ingress staging range)
 *   MR2 = packet_len
 *   MR3 = responder ephemeral-private offset (type 1 only, 32 bytes)
 *   MR4 = responder sender_index (type 1 only, non-zero)
 *   Reply for type 1: MR1 = TX offset; MR2 = response length (92)
 *   Reply for type 2: MR1 = peer_id; MR2 = 0
 *   Reply for type 4: MR1 = peer_id; MR2 = plaintext length
 *
 *   Type 4 payloads are released to WG_STAGING_RX_OFF only after AEAD and
 *   replay-window validation. Cookie messages are not yet supported.
 */
#define OP_WG_INGEST          0xD8u

/* ── Result codes (MR0 in replies) ──────────────────────────────────────── */
#define WG_OK               0u   /* success */
#define WG_ERR_NOPEER       1u   /* peer_id not found or not active */
#define WG_ERR_NOKEY        2u   /* local private key not yet configured */
#define WG_ERR_FULL         3u   /* peer table full (WG_MAX_PEERS reached) */
#define WG_ERR_CRYPTO       4u   /* cryptographic operation failed */
#define WG_ERR_NOSESSION    5u   /* authenticated Noise session not established */

/* ── Peer table entry ────────────────────────────────────────────────────── */
/*
 * Stored statically in the wg_net PD's BSS (peers[WG_MAX_PEERS]).
 * Public for documentation and test-harness purposes.
 */
typedef struct {
    uint8_t   peer_id;                  /* 0..WG_MAX_PEERS-1; only valid when active */
    bool      active;                   /* true if this slot is in use */
    uint8_t   pubkey[WG_KEY_LEN];       /* peer's Curve25519 public key */
    uint8_t   preshared_key[WG_KEY_LEN];/* optional pre-shared key (zeros = none) */
    uint32_t  endpoint_ip;              /* UDP endpoint IPv4, network byte order */
    uint16_t  endpoint_port;            /* UDP endpoint port, host byte order */
    uint8_t   _ep_pad[2];               /* alignment */
    uint32_t  allowed_ip;               /* allowed-IP network address, net byte order */
    uint32_t  allowed_mask;             /* subnet mask, host byte order */
    uint64_t  tx_bytes;                 /* encrypted bytes sent to this peer */
    uint64_t  rx_bytes;                 /* decrypted bytes received from this peer */
    uint64_t  tx_counter;               /* next transport nonce counter */
    wg_replay_window_t rx_replay;       /* authenticated RX counter window */
    wg_noise_handshake_t handshake;     /* in-progress Noise_IKpsk2 transcript */
    uint8_t   send_key[WG_KEY_LEN];      /* current transport send key */
    uint8_t   receive_key[WG_KEY_LEN];   /* current transport receive key */
    uint32_t  send_index;                /* peer's current receiver index */
    uint32_t  receive_index;             /* our current receiver index */
    bool      session_established;       /* transport keys are authenticated */
    uint8_t   _session_pad[3];
    uint8_t   last_timestamp[WG_NOISE_TIMESTAMP_LEN]; /* replay floor */
    uint32_t  last_handshake;           /* monotonic tick of last successful handshake */
    uint8_t   _pad[4];                  /* explicit pad to 8-byte alignment */
} wg_peer_t;                            /* includes a 1 KiB replay bitmap */

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
 *   freestanding crypto library. NetServer UDP/IP encapsulation preserves
 *   Headscale/netmap endpoints. Packed netmap apply, rekey-after-time,
 *   cookie-reply / under-load mac2, entropy-backed ephemeral/index
 *   (after OP_WG_SEED_ENTROPY), DERP frame wrap/unwrap (OP_WG_DERP_*),
 *   per-peer path mode (direct UDP vs DERP framing), and timer-tick rekey
 *   are host-proven here. Live TLS DERP sockets and Tailscale Noise
 *   control-plane login remain outer-transport / follow-on work.
 *
 * Copyright (c) 2026 The FractalOS Project
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
#define WG_STAGING_COOKIE_NONCE_OFF 0x000080u
#define WG_STAGING_PEER_KEY_OFF   0x001000u
#define WG_STAGING_TX_OFF         0x002000u
#define WG_STAGING_RX_OFF         0x010000u
#define WG_STAGING_TX_MAX         0x00E000u
#define WG_STAGING_RX_MAX         0x00E000u
#define WG_STAGING_INGRESS_OFF    0x011000u

/* ── Keepalive / rekey intervals (WireGuard spec §6.1 / §6.4) ───────────── */
#define WG_KEEPALIVE_SECS      25u  /* send keepalive if no traffic for 25s */
#define WG_REKEY_AFTER_SECS   120u  /* initiate rekey after this age */
#define WG_REJECT_AFTER_SECS  180u  /* drop session if older than this */
#define WG_COOKIE_SECRET_MAX_AGE 120u /* rotate cookie secret every 2 min */
#define WG_COOKIE_SECRET_LATENCY   5u /* stop using cookies this early */

/* Packed Headscale/netmap peer record (staging blob for OP_WG_APPLY_NETMAP). */
#define WG_NETMAP_VERSION        1u
#define WG_NETMAP_PEER_BYTES     48u
#define WG_NETMAP_HEADER_BYTES   8u

struct wg_netmap_peer {
    uint8_t  pubkey[WG_KEY_LEN];
    uint32_t endpoint_ip;    /* IPv4, same endianness as OP_WG_ADD_PEER */
    uint16_t endpoint_port;
    uint16_t reserved;
    uint32_t allowed_ip;
    uint32_t allowed_mask;
} __attribute__((packed));

struct wg_netmap_header {
    uint32_t version;     /* WG_NETMAP_VERSION */
    uint32_t peer_count;  /* <= WG_MAX_PEERS */
} __attribute__((packed));
_Static_assert(sizeof(struct wg_netmap_peer) == WG_NETMAP_PEER_BYTES,
               "netmap peer wire size");
_Static_assert(sizeof(struct wg_netmap_header) == WG_NETMAP_HEADER_BYTES,
               "netmap header wire size");

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
 *   MR2 = ephemeral_private_offset (32 bytes) OR 0 to draw from entropy
 *   MR3 = TAI64N timestamp_offset (12 bytes) OR 0 to synthesize from timer
 *   MR4 = sender_index OR 0 to allocate a fresh non-zero unused index
 *   Reply: MR0 = result; MR1 = TX offset; MR2 = message length (148);
 *          MR3 = sender_index actually used
 *
 *   Auto paths require a prior OP_WG_SEED_ENTROPY (or future entropy-service
 *   binding). Explicit non-zero offsets/index keep the prior test vectors.
 */
#define OP_WG_HANDSHAKE_START 0xD7u

/*
 * OP_WG_INGEST (0xD8) — authenticate an incoming WireGuard packet
 *   MR1 = packet_offset (absolute offset in the RX ingress staging range)
 *   MR2 = packet_len
 *   MR3 = responder ephemeral-private offset (type 1) OR 0 = entropy
 *   MR4 = responder sender_index (type 1) OR 0 = allocate
 *   Reply for type 1: MR1 = TX offset; MR2 = response length (92);
 *                     MR3 = sender_index used
 *   Reply for type 2: MR1 = peer_id; MR2 = 0
 *   Reply for type 4: MR1 = peer_id; MR2 = plaintext length
 *
 *   Type 4 payloads are released to WG_STAGING_RX_OFF only after AEAD and
 *   replay-window validation.
 *   Type 3 (cookie reply): decrypts cookie for the peer matching receiver
 *   index; requires a prior initiation mac1 on that peer.
 *   Under load (OP_WG_SET_UNDER_LOAD): type 1/2 with valid mac1 but missing
 *   or invalid mac2 emit a cookie reply instead of Noise processing.
 *   Optional MR5 = src_ipv4 octets packed LE; MR6 = src_udp_port (host).
 *   Cookie-reply nonce is read from WG_STAGING_COOKIE_NONCE_OFF (24 bytes);
 *   if that region is all zeros, a nonce is drawn from entropy when seeded.
 */
#define OP_WG_INGEST          0xD8u

/*
 * OP_WG_APPLY_NETMAP (0xD9) — sync peers from a packed Headscale-style netmap
 *   MR1 = netmap_offset (absolute offset into wg_staging)
 *   MR2 = netmap_bytes  (header + peer_count * WG_NETMAP_PEER_BYTES)
 *   Reply: MR0 = result; MR1 = peers_applied; MR2 = peers_removed;
 *          MR3 = endpoints_roamed (pubkey match, session retained)
 *
 *   Matching public keys update endpoint/allowed-IP without wiping the
 *   authenticated session (endpoint roaming via control-plane netmap).
 *   Peers absent from the map are removed.
 */
#define OP_WG_APPLY_NETMAP    0xD9u

/*
 * OP_WG_SET_UNDER_LOAD (0xDA) — enable/disable cookie DoS gate
 *   MR1 = 1 under load (require mac2), 0 normal
 *   Reply: MR0 = WG_OK
 */
#define OP_WG_SET_UNDER_LOAD  0xDAu

/*
 * OP_WG_SET_COOKIE_SECRET (0xDB) — install 32-byte cookie MAC secret
 *   MR1 = staging offset of 32-byte secret (host/test until entropy path)
 *   Reply: MR0 = WG_OK
 */
#define OP_WG_SET_COOKIE_SECRET 0xDBu

/*
 * OP_WG_SEED_ENTROPY (0xDC) — seed the local keyed-BLAKE2s DRBG
 *   MR1 = staging offset of 32-byte seed (KEY quality material)
 *   Reply: MR0 = WG_OK
 *
 *   Until the entropy-service PD is fully wired, this is the authorized
 *   way for tests and boot to unlock auto ephemeral/index generation.
 *   Production boot must seed from ENTROPY_SVC_OP_GET_BYTES (KEY quality).
 */
#define OP_WG_SEED_ENTROPY    0xDCu

/*
 * OP_WG_DERP_WRAP (0xDD) — frame WireGuard ciphertext as DERP SendPacket
 *   MR1 = peer_id (destination; uses peer's stored Curve25519 pubkey)
 *   MR2 = ciphertext_offset (absolute offset into wg_staging)
 *   MR3 = ciphertext_len
 *   MR4 = out_offset (absolute offset for framed DERP bytes)
 *   Reply: MR0 = result; MR1 = out_offset; MR2 = frame_len
 *
 *   Blind framing only — ciphertext is never decrypted. Frame type is
 *   FrameSendPacket (0x04): 32B dest pubkey + packet.
 */
#define OP_WG_DERP_WRAP       0xDDu

/*
 * OP_WG_DERP_UNWRAP (0xDE) — parse DERP Recv/Send/Forward → ciphertext
 *   MR1 = frame_offset
 *   MR2 = frame_len (header + payload)
 *   MR3 = out_offset (absolute offset for extracted ciphertext)
 *   Reply: MR0 = result; MR1 = peer_id (matched src/dest pubkey);
 *          MR2 = ciphertext_len; MR3 = frame_type
 *
 *   Accepts FrameRecvPacket (0x05), FrameSendPacket (0x04), and
 *   FrameForwardPacket (0x0a). Peer match is against the table pubkey
 *   that identifies the remote (src for Recv/Forward, dest for Send).
 */
#define OP_WG_DERP_UNWRAP     0xDEu

/*
 * OP_WG_SET_PATH_MODE (0xDF) — select direct UDP vs DERP fallback per peer
 *   MR1 = peer_id
 *   MR2 = mode (WG_PATH_DIRECT=0, WG_PATH_DERP=1)
 *   Reply: MR0 = result
 *
 *   DERP mode (or a zero endpoint_ip) causes OP_WG_SEND to frame ciphertext
 *   as FrameSendPacket into WG_STAGING_INGRESS_OFF instead of OP_NET_WG_UDP_SEND.
 *   Live TLS/WebSocket to a DERP server remains an outer transport concern.
 */
#define OP_WG_SET_PATH_MODE   0xDFu

/*
 * OP_WG_TIMER_TICK (0xE0) — advance keepalive / rekey clock by one second
 *   Reply: MR0 = WG_OK; MR1 = timer_tick after advance
 */
#define OP_WG_TIMER_TICK      0xE0u

#define WG_PATH_DIRECT        0u
#define WG_PATH_DERP          1u

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
    uint8_t   path_mode;                /* WG_PATH_DIRECT or WG_PATH_DERP */
    uint8_t   _ep_pad;                  /* alignment */
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
    uint8_t   latest_cookie[WG_NOISE_COOKIE_LEN]; /* decrypted cookie for mac2 */
    uint8_t   last_mac1_sent[WG_NOISE_MAC_LEN];   /* AAD for cookie reply */
    uint32_t  cookie_birth;             /* timer_tick when cookie installed */
    bool      cookie_valid;
    bool      have_sent_mac1;
    uint8_t   _cookie_pad[2];
} wg_peer_t;                            /* includes a 1 KiB replay bitmap */

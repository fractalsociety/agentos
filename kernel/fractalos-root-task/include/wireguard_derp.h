/*
 * wireguard_derp.h — Tailscale-compatible DERP frame codec (freestanding)
 *
 * DERP is a blind relay: peers are addressed by WireGuard Curve25519 public
 * keys. This module only frames/unframes ciphertext; it never decrypts.
 *
 * Wire format (Tailscale derp/derp.go):
 *   [1]  frame type
 *   [4]  payload length (big-endian)
 *   [N]  payload
 *
 * Magic (FrameServerKey): "DERP🔑" = 44 45 52 50 f0 9f 94 91
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define WG_DERP_HDR_LEN           5u
#define WG_DERP_KEY_LEN           32u
#define WG_DERP_MAGIC_LEN         8u
#define WG_DERP_MAX_PACKET        (64u << 10) /* Tailscale MaxPacketSize */

#define WG_DERP_FRAME_SERVER_KEY  0x01u
#define WG_DERP_FRAME_CLIENT_INFO 0x02u
#define WG_DERP_FRAME_SERVER_INFO 0x03u
#define WG_DERP_FRAME_SEND_PACKET 0x04u /* 32B dest + packet */
#define WG_DERP_FRAME_RECV_PACKET 0x05u /* v2: 32B src + packet */
#define WG_DERP_FRAME_KEEP_ALIVE  0x06u
#define WG_DERP_FRAME_NOTE_PREF   0x07u
#define WG_DERP_FRAME_PEER_GONE   0x08u
#define WG_DERP_FRAME_PEER_PRESENT 0x09u
#define WG_DERP_FRAME_FWD_PACKET  0x0au /* 32B src + 32B dst + packet */
#define WG_DERP_FRAME_PING        0x12u
#define WG_DERP_FRAME_PONG        0x13u

/* "DERP🔑" — 8 bytes including UTF-8 key emoji */
extern const uint8_t wg_derp_magic[WG_DERP_MAGIC_LEN];

/*
 * Parse the 5-byte frame header. Returns 0 on success, -1 on truncate /
 * oversized payload (> WG_DERP_MAX_PACKET).
 */
int wg_derp_parse_header(const uint8_t *in, size_t in_len,
                         uint8_t *type_out, uint32_t *payload_len_out);

/*
 * Write a 5-byte header. Returns bytes written (5) or -1.
 */
int wg_derp_write_header(uint8_t *out, size_t out_cap,
                         uint8_t type, uint32_t payload_len);

/*
 * Encode FrameSendPacket: dest pubkey + opaque WG ciphertext.
 * *out_len receives total framed size (header + payload).
 */
int wg_derp_encode_send_packet(uint8_t *out, size_t out_cap,
                               const uint8_t dest_pub[WG_DERP_KEY_LEN],
                               const uint8_t *pkt, uint32_t pkt_len,
                               uint32_t *out_len);

/*
 * Encode FrameRecvPacket (v2): src pubkey + opaque packet (server→client).
 */
int wg_derp_encode_recv_packet(uint8_t *out, size_t out_cap,
                               const uint8_t src_pub[WG_DERP_KEY_LEN],
                               const uint8_t *pkt, uint32_t pkt_len,
                               uint32_t *out_len);

/*
 * Encode FrameForwardPacket: src + dest + opaque packet.
 */
int wg_derp_encode_forward_packet(uint8_t *out, size_t out_cap,
                                  const uint8_t src_pub[WG_DERP_KEY_LEN],
                                  const uint8_t dest_pub[WG_DERP_KEY_LEN],
                                  const uint8_t *pkt, uint32_t pkt_len,
                                  uint32_t *out_len);

/*
 * Decode Send/Recv/Forward payloads. pkt_out may alias into frame_payload.
 * Returns 0 on success, -1 on truncate / wrong layout.
 */
int wg_derp_decode_send_packet(const uint8_t *payload, uint32_t payload_len,
                               const uint8_t **dest_pub_out,
                               const uint8_t **pkt_out, uint32_t *pkt_len_out);

int wg_derp_decode_recv_packet(const uint8_t *payload, uint32_t payload_len,
                               const uint8_t **src_pub_out,
                               const uint8_t **pkt_out, uint32_t *pkt_len_out);

int wg_derp_decode_forward_packet(const uint8_t *payload, uint32_t payload_len,
                                  const uint8_t **src_pub_out,
                                  const uint8_t **dest_pub_out,
                                  const uint8_t **pkt_out,
                                  uint32_t *pkt_len_out);

/*
 * Validate FrameServerKey magic prefix. pubkey_out may be NULL.
 * payload must begin with Magic (+ optional 32B server public key).
 */
int wg_derp_check_server_key(const uint8_t *payload, uint32_t payload_len,
                             const uint8_t **pubkey_out);

/*
 * Encode Ping or Pong with an opaque 8-byte data blob (Tailscale uses
 * time/data; we treat it as opaque for L2 round-trip).
 */
int wg_derp_encode_ping_pong(uint8_t *out, size_t out_cap, uint8_t type,
                             const uint8_t data[8], uint32_t *out_len);

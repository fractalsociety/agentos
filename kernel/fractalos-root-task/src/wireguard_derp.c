/*
 * wireguard_derp.c — Tailscale-compatible DERP frame codec
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "wireguard_derp.h"

/* DERP🔑 — UTF-8 for U+1F511 KEY */
const uint8_t wg_derp_magic[WG_DERP_MAGIC_LEN] = {
    0x44u, 0x45u, 0x52u, 0x50u, 0xf0u, 0x9fu, 0x94u, 0x91u
};

static uint32_t derp_rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void derp_wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int derp_encode_keyed(uint8_t *out, size_t out_cap, uint8_t type,
                             const uint8_t *k1, const uint8_t *k2,
                             const uint8_t *pkt, uint32_t pkt_len,
                             uint32_t *out_len)
{
    uint32_t keys = (k1 != (const uint8_t *)0 ? WG_DERP_KEY_LEN : 0u)
                  + (k2 != (const uint8_t *)0 ? WG_DERP_KEY_LEN : 0u);
    uint32_t payload_len;
    uint32_t total;
    uint32_t off;

    if (pkt_len > WG_DERP_MAX_PACKET)
        return -1;
    payload_len = keys + pkt_len;
    if (payload_len < keys) /* overflow */
        return -1;
    total = WG_DERP_HDR_LEN + payload_len;
    if (total < WG_DERP_HDR_LEN || total > out_cap)
        return -1;
    if (wg_derp_write_header(out, out_cap, type, payload_len) < 0)
        return -1;
    off = WG_DERP_HDR_LEN;
    if (k1 != (const uint8_t *)0) {
        for (uint32_t i = 0u; i < WG_DERP_KEY_LEN; i++)
            out[off + i] = k1[i];
        off += WG_DERP_KEY_LEN;
    }
    if (k2 != (const uint8_t *)0) {
        for (uint32_t i = 0u; i < WG_DERP_KEY_LEN; i++)
            out[off + i] = k2[i];
        off += WG_DERP_KEY_LEN;
    }
    for (uint32_t i = 0u; i < pkt_len; i++)
        out[off + i] = pkt[i];
    if (out_len != (uint32_t *)0)
        *out_len = total;
    return 0;
}

int wg_derp_parse_header(const uint8_t *in, size_t in_len,
                         uint8_t *type_out, uint32_t *payload_len_out)
{
    uint32_t plen;

    if (in == (const uint8_t *)0 || type_out == (uint8_t *)0
        || payload_len_out == (uint32_t *)0 || in_len < WG_DERP_HDR_LEN)
        return -1;
    *type_out = in[0];
    plen = derp_rd_be32(in + 1);
    if (plen > WG_DERP_MAX_PACKET)
        return -1;
    *payload_len_out = plen;
    return 0;
}

int wg_derp_write_header(uint8_t *out, size_t out_cap,
                         uint8_t type, uint32_t payload_len)
{
    if (out == (uint8_t *)0 || out_cap < WG_DERP_HDR_LEN
        || payload_len > WG_DERP_MAX_PACKET)
        return -1;
    out[0] = type;
    derp_wr_be32(out + 1, payload_len);
    return (int)WG_DERP_HDR_LEN;
}

int wg_derp_encode_send_packet(uint8_t *out, size_t out_cap,
                               const uint8_t dest_pub[WG_DERP_KEY_LEN],
                               const uint8_t *pkt, uint32_t pkt_len,
                               uint32_t *out_len)
{
    if (dest_pub == (const uint8_t *)0
        || (pkt == (const uint8_t *)0 && pkt_len != 0u))
        return -1;
    return derp_encode_keyed(out, out_cap, WG_DERP_FRAME_SEND_PACKET,
                             dest_pub, (const uint8_t *)0, pkt, pkt_len,
                             out_len);
}

int wg_derp_encode_recv_packet(uint8_t *out, size_t out_cap,
                               const uint8_t src_pub[WG_DERP_KEY_LEN],
                               const uint8_t *pkt, uint32_t pkt_len,
                               uint32_t *out_len)
{
    if (src_pub == (const uint8_t *)0
        || (pkt == (const uint8_t *)0 && pkt_len != 0u))
        return -1;
    return derp_encode_keyed(out, out_cap, WG_DERP_FRAME_RECV_PACKET,
                             src_pub, (const uint8_t *)0, pkt, pkt_len,
                             out_len);
}

int wg_derp_encode_forward_packet(uint8_t *out, size_t out_cap,
                                  const uint8_t src_pub[WG_DERP_KEY_LEN],
                                  const uint8_t dest_pub[WG_DERP_KEY_LEN],
                                  const uint8_t *pkt, uint32_t pkt_len,
                                  uint32_t *out_len)
{
    if (src_pub == (const uint8_t *)0 || dest_pub == (const uint8_t *)0
        || (pkt == (const uint8_t *)0 && pkt_len != 0u))
        return -1;
    return derp_encode_keyed(out, out_cap, WG_DERP_FRAME_FWD_PACKET,
                             src_pub, dest_pub, pkt, pkt_len, out_len);
}

int wg_derp_decode_send_packet(const uint8_t *payload, uint32_t payload_len,
                               const uint8_t **dest_pub_out,
                               const uint8_t **pkt_out, uint32_t *pkt_len_out)
{
    if (payload == (const uint8_t *)0 || dest_pub_out == (const uint8_t **)0
        || pkt_out == (const uint8_t **)0 || pkt_len_out == (uint32_t *)0
        || payload_len < WG_DERP_KEY_LEN)
        return -1;
    *dest_pub_out = payload;
    *pkt_out = payload + WG_DERP_KEY_LEN;
    *pkt_len_out = payload_len - WG_DERP_KEY_LEN;
    return 0;
}

int wg_derp_decode_recv_packet(const uint8_t *payload, uint32_t payload_len,
                               const uint8_t **src_pub_out,
                               const uint8_t **pkt_out, uint32_t *pkt_len_out)
{
    /* Same layout as Send for v2 RecvPacket. */
    return wg_derp_decode_send_packet(payload, payload_len, src_pub_out,
                                      pkt_out, pkt_len_out);
}

int wg_derp_decode_forward_packet(const uint8_t *payload, uint32_t payload_len,
                                  const uint8_t **src_pub_out,
                                  const uint8_t **dest_pub_out,
                                  const uint8_t **pkt_out,
                                  uint32_t *pkt_len_out)
{
    if (payload == (const uint8_t *)0 || src_pub_out == (const uint8_t **)0
        || dest_pub_out == (const uint8_t **)0
        || pkt_out == (const uint8_t **)0 || pkt_len_out == (uint32_t *)0
        || payload_len < (WG_DERP_KEY_LEN * 2u))
        return -1;
    *src_pub_out = payload;
    *dest_pub_out = payload + WG_DERP_KEY_LEN;
    *pkt_out = payload + (WG_DERP_KEY_LEN * 2u);
    *pkt_len_out = payload_len - (WG_DERP_KEY_LEN * 2u);
    return 0;
}

int wg_derp_check_server_key(const uint8_t *payload, uint32_t payload_len,
                             const uint8_t **pubkey_out)
{
    if (payload == (const uint8_t *)0 || payload_len < WG_DERP_MAGIC_LEN)
        return -1;
    for (uint32_t i = 0u; i < WG_DERP_MAGIC_LEN; i++) {
        if (payload[i] != wg_derp_magic[i])
            return -1;
    }
    if (pubkey_out != (const uint8_t **)0) {
        if (payload_len >= WG_DERP_MAGIC_LEN + WG_DERP_KEY_LEN)
            *pubkey_out = payload + WG_DERP_MAGIC_LEN;
        else
            *pubkey_out = (const uint8_t *)0;
    }
    return 0;
}

int wg_derp_encode_ping_pong(uint8_t *out, size_t out_cap, uint8_t type,
                             const uint8_t data[8], uint32_t *out_len)
{
    if (type != WG_DERP_FRAME_PING && type != WG_DERP_FRAME_PONG)
        return -1;
    if (data == (const uint8_t *)0)
        return -1;
    return derp_encode_keyed(out, out_cap, type, (const uint8_t *)0,
                             (const uint8_t *)0, data, 8u, out_len);
}

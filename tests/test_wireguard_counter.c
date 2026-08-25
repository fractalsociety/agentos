#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/wireguard_counter.h"

static int failures;
#define CHECK(condition, description) do {                              \
    if (condition) printf("ok - %s\n", description);                   \
    else { printf("not ok - %s\n", description); failures++; }        \
} while (0)

int main(void)
{
    uint8_t nonce[12];
    uint64_t tx = 0u;
    CHECK(wg_transport_next_counter(&tx, nonce) && tx == 1u,
          "first send counter is allocated once");
    static const uint8_t zero_nonce[12] = {0};
    CHECK(memcmp(nonce, zero_nonce, sizeof(nonce)) == 0,
          "counter zero encodes as the WireGuard zero nonce");
    CHECK(wg_transport_next_counter(&tx, nonce) && nonce[4] == 1u,
          "transport counter is encoded little-endian after four zero bytes");
    tx = WG_REJECT_AFTER_MESSAGES;
    CHECK(!wg_transport_next_counter(&tx, nonce),
          "send counter fails closed at WireGuard's rejection limit");

    wg_replay_window_t replay;
    wg_replay_window_reset(&replay);
    CHECK(wg_replay_window_accept(&replay, 0u),
          "replay window accepts the first authenticated packet");
    CHECK(!wg_replay_window_accept(&replay, 0u),
          "replay window rejects an immediate duplicate");
    CHECK(wg_replay_window_accept(&replay, 64u),
          "replay window advances across a bitmap word boundary");
    CHECK(wg_replay_window_accept(&replay, 63u),
          "replay window accepts an unseen out-of-order packet");
    CHECK(!wg_replay_window_accept(&replay, 63u),
          "replay window rejects an out-of-order duplicate");
    CHECK(wg_replay_window_accept(&replay, WG_REPLAY_WINDOW_BITS),
          "replay window advances by a full window");
    CHECK(!wg_replay_window_accept(&replay, 0u),
          "replay window rejects a packet that has fallen out of the window");
    CHECK(wg_replay_window_accept(&replay, 1u),
          "oldest unseen packet still inside the window is accepted");
    CHECK(!wg_replay_window_accept(&replay, WG_REJECT_AFTER_MESSAGES),
          "receive counter fails closed at WireGuard's rejection limit");

    printf("1..13\n");
    return failures == 0 ? 0 : 1;
}

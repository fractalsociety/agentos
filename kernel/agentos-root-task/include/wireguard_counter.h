/* WireGuard transport counters and RFC 6479-style sliding replay window. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define WG_REPLAY_WINDOW_BITS  8192u
#define WG_REPLAY_WINDOW_WORDS (WG_REPLAY_WINDOW_BITS / 64u)
#define WG_REJECT_AFTER_MESSAGES \
    (UINT64_MAX - (uint64_t)WG_REPLAY_WINDOW_BITS - 1u)

typedef struct {
    uint64_t top;
    uint64_t bitmap[WG_REPLAY_WINDOW_WORDS];
    bool initialized;
} wg_replay_window_t;

static inline void wg_replay_window_reset(wg_replay_window_t *window)
{
    window->top = 0u;
    window->initialized = false;
    for (uint32_t i = 0; i < WG_REPLAY_WINDOW_WORDS; i++)
        window->bitmap[i] = 0u;
}

static inline uint32_t wg_replay_word(uint64_t counter)
{
    return (uint32_t)((counter >> 6) & (WG_REPLAY_WINDOW_WORDS - 1u));
}

static inline uint64_t wg_replay_bit(uint64_t counter)
{
    return UINT64_C(1) << (counter & 63u);
}

static inline void wg_replay_clear_advanced(wg_replay_window_t *window,
                                             uint64_t first,
                                             uint64_t last)
{
    while (first <= last && (first & 63u) != 0u) {
        window->bitmap[wg_replay_word(first)] &= ~wg_replay_bit(first);
        first++;
    }
    while (first <= last && last - first >= 63u) {
        window->bitmap[wg_replay_word(first)] = 0u;
        first += 64u;
    }
    while (first <= last) {
        window->bitmap[wg_replay_word(first)] &= ~wg_replay_bit(first);
        first++;
    }
}

/* Authenticate first, then call this exactly once for the received counter. */
static inline bool wg_replay_window_accept(wg_replay_window_t *window,
                                            uint64_t counter)
{
    if (counter >= WG_REJECT_AFTER_MESSAGES) return false;
    if (!window->initialized) {
        wg_replay_window_reset(window);
        window->initialized = true;
        window->top = counter;
        window->bitmap[wg_replay_word(counter)] |= wg_replay_bit(counter);
        return true;
    }

    if (counter > window->top) {
        uint64_t delta = counter - window->top;
        if (delta >= WG_REPLAY_WINDOW_BITS) {
            for (uint32_t i = 0; i < WG_REPLAY_WINDOW_WORDS; i++)
                window->bitmap[i] = 0u;
        } else {
            wg_replay_clear_advanced(window, window->top + 1u, counter);
        }
        window->top = counter;
    } else if (window->top - counter >= WG_REPLAY_WINDOW_BITS) {
        return false;
    }

    uint32_t word = wg_replay_word(counter);
    uint64_t bit = wg_replay_bit(counter);
    if ((window->bitmap[word] & bit) != 0u) return false;
    window->bitmap[word] |= bit;
    return true;
}

/* WireGuard's AEAD nonce is four zero bytes followed by a LE64 counter. */
static inline void wg_transport_counter_nonce(uint64_t counter,
                                               uint8_t nonce[12])
{
    nonce[0] = 0u; nonce[1] = 0u; nonce[2] = 0u; nonce[3] = 0u;
    for (uint32_t i = 0; i < 8u; i++)
        nonce[4u + i] = (uint8_t)(counter >> (i * 8u));
}

static inline bool wg_transport_next_counter(uint64_t *counter,
                                              uint8_t nonce[12])
{
    if (*counter >= WG_REJECT_AFTER_MESSAGES) return false;
    wg_transport_counter_nonce(*counter, nonce);
    (*counter)++;
    return true;
}

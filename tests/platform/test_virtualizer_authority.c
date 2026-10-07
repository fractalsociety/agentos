#include <stdio.h>
#include <contracts/virtualizer_authority.h>
#include <contracts/blk_virt_contract.h>

int main(void)
{
    const uint64_t badges[] = {0, VIRT_CLIENT_BADGE_PRIMARY,
        VIRT_CLIENT_BADGE_SECONDARY, VIRT_NET_BADGE_NATIVE,
        VIRT_BLOCK_BADGE_NATIVE, UINT64_MAX,
        VIRT_CLIENT_BADGE_PRIMARY | (UINT64_C(1) << 32)};
    unsigned checked = 0;
    for (unsigned b = 0; b < sizeof(badges) / sizeof(badges[0]); ++b) {
        for (uint32_t client = 0; client < 4; ++client) {
            for (uint32_t slot = 0; slot < 4; ++slot) {
                bool expected = (b == 1 && client == 0 && slot == 0) ||
                                (b == 2 && client == 1 && slot == 1);
                if (virt_client_authorized(badges[b], client, slot) != expected)
                    return fprintf(stderr, "FAIL client authority b=%u c=%u s=%u\n",
                                   b, client, slot), 1;
                bool net_expected = expected ||
                    (badges[b] == VIRT_NET_BADGE_NATIVE && client == 2 && slot == 2);
                if (virt_net_authorized(badges[b], client, slot) != net_expected)
                    return fprintf(stderr, "FAIL network authority\n"), 1;
                for (uint32_t media = 0; media < 4; ++media) {
                    bool block_expected = expected && media == slot;
#ifdef AGENTOS_FRACTAL_NATIVE_PROBE
                    block_expected |= badges[b] == VIRT_BLOCK_BADGE_NATIVE &&
                        client == 2 && slot == 2 && media == 1;
#endif
                    if (virt_media_authorized(badges[b], client, slot, media) !=
                        block_expected)
                        return fprintf(stderr, "FAIL media authority\n"), 1;
                    ++checked;
                }
            }
        }
    }
    if (virt_client_badge(UINT32_MAX) != 0 ||
        virt_client_authorized(VIRT_CLIENT_BADGE_PRIMARY, UINT32_MAX, UINT32_MAX) ||
        virt_media_authorized(VIRT_CLIENT_BADGE_SECONDARY, 1, 1, UINT32_MAX))
        return fprintf(stderr, "FAIL overflow authority\n"), 1;
#ifdef AGENTOS_FRACTAL_NATIVE_PROBE
    if (!blk_virt_service_notification(4u) ||
        !blk_virt_service_notification(7u) ||
        blk_virt_service_notification(8u) ||
        blk_virt_service_notification(VIRT_BLOCK_BADGE_NATIVE))
        return fprintf(stderr, "FAIL native block notification boundary\n"), 1;
#endif
    printf("PASS: virtualizer authority rejects spoofed identity/media (%u cases)\n", checked);
    return 0;
}

#include <platform/fractal_nvme_target.h>
#include <assert.h>

int main(void)
{
    uint32_t selector = 0u, identity = 0u;
    assert(fractal_nvme_target_config(FRACTAL_NVME_TARGET_QEMU_SLOT9,
                                      &selector, &identity));
    assert(selector == UINT32_C(0x80004800));
    assert(identity == UINT32_C(0x00101b36));
    assert(fractal_nvme_target_config(FRACTAL_NVME_TARGET_QEMU_BUS81,
                                      &selector, &identity));
    assert(selector == UINT32_C(0x80810000));
    assert(identity == UINT32_C(0x00101b36));
    assert(fractal_nvme_target_config(FRACTAL_NVME_TARGET_SAMSUNG_BUS81,
                                      &selector, &identity));
    assert(selector == UINT32_C(0x80810000));
    assert(identity == UINT32_C(0xa80d144d));
    assert(!fractal_nvme_target_config(3u, &selector, &identity));
    assert(selector == 0u && identity == 0u);
    assert(!fractal_nvme_target_config(0u, 0, &identity));
    assert(!fractal_nvme_target_config(0u, &selector, 0));
    return 0;
}

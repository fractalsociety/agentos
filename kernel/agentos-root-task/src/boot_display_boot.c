/* Boot-only capability provisioning for the firmware framebuffer driver. */
#include "boot_info.h"
#include "ut_alloc.h"
#include "pd_vspace.h"
#include "system_desc.h"
#include <platform/boot_display.h>
#include <platform/display_layout.h>
static aos_boot_fb_t metadata;
static seL4_CPtr queue_frame, progress_frame, metadata_frame;
int boot_display_allocate(const seL4_BootInfo *bi)
{
    if (!bi || !bi->extraLen || bi->extraLen>1024u*1024u ||
        aos_boot_fb_parse((void *)((uintptr_t)bi+4096u),bi->extraLen,&metadata)) return -1;
    if (ut_alloc_cap(seL4_ARCH_LargePageObject,0,&queue_frame) ||
        ut_alloc_cap(seL4_ARCH_LargePageObject,0,&progress_frame) ||
        ut_alloc_cap(seL4_ARCH_LargePageObject,0,&metadata_frame)) return -1;
    if (pd_vspace_map_device_frame(seL4_CapInitThreadVSpace,metadata_frame,AOS_BOOT_FB_META_VA)) return -1;
    *(aos_boot_fb_t *)AOS_BOOT_FB_META_VA=metadata;
    AGENTOS_MEMORY_FENCE();
    return seL4_ARCH_Page_Unmap(metadata_frame)==seL4_NoError ? 0 : -1;
}
static int share(seL4_CPtr frame,seL4_CPtr vspace,seL4_Word va,int write)
{
    seL4_CPtr copy=ut_alloc_slot();
    if (!copy || seL4_CNode_Copy(seL4_CapInitThreadCNode,copy,64,
        seL4_CapInitThreadCNode,frame,64,write ? seL4_AllRights : seL4_CanRead)) return -1;
    return pd_vspace_map_reserved_region(vspace,va,&copy,1,write)==seL4_NoError ? 0 : -1;
}
int boot_display_grant(uint32_t service,seL4_CPtr vspace)
{
    if (service==SVC_ID_BOOT_SCREEN || service==SVC_ID_BOOT_DISPLAY)
        if (share(queue_frame,vspace,AOS_DISPLAY_QUEUE_VA,1)) return -1;
    if (service==SVC_ID_BOOT_SCREEN || service==SVC_ID_FRACTAL_NATIVE_PROBE ||
        service==SVC_ID_FRACTAL_NVME_PROBE)
        if (share(progress_frame,vspace,AOS_BOOT_PROGRESS_VA,service!=SVC_ID_BOOT_SCREEN)) return -1;
    if (service!=SVC_ID_BOOT_DISPLAY) return 0;
    if (share(metadata_frame,vspace,AOS_BOOT_FB_META_VA,0) ||
        pd_vspace_map_region(vspace,AOS_DISPLAY_BANK_VA,2u*AOS_DISPLAY_BANK_STRIDE,1)) return -1;
    /* Only this driver VSpace receives physical framebuffer mappings. No
     * device caps, paging caps, IRQs or framebuffer mapping reach the UI. */
    for (uint64_t offset=0;offset<metadata.bytes;offset+=4096u) {
        seL4_CPtr frame;
        if (ut_alloc_device_cap(metadata.physical+offset,&frame) ||
            pd_vspace_map_uncached_device_frame(vspace,frame,AOS_BOOT_FB_VA+offset)) return -1;
    }
    return 0;
}

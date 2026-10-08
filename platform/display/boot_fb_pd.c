#include <platform/boot_display.h>
#include <platform/display.h>
#include <platform/display_layout.h>
#include "agentos.h"
#include <sel4/sel4.h>
static aos_display_driver_t driver;
static aos_boot_fb_t metadata;
static int present(void *unused,unsigned bank,uint32_t width,uint32_t height)
{
    (void)unused;
    if (bank>1) return -1;
    int result=aos_boot_fb_present(&metadata,(void *)AOS_BOOT_FB_VA,
        (void *)(AOS_DISPLAY_BANK_VA+bank*AOS_DISPLAY_BANK_STRIDE),width,height);
    static unsigned first;
    if (!first && !result) {
        agentos_log_info("boot_display","BOOT_DISPLAY_PRESENT");
        first=1;
    }
    return result;
}
void pd_main(seL4_CPtr endpoint,seL4_CPtr nameserver)
{
    (void)endpoint; (void)nameserver;
    metadata=*(const aos_boot_fb_t *)AOS_BOOT_FB_META_VA;
    if (!aos_boot_fb_valid(&metadata) || aos_display_init(&driver,
        (void *)AOS_DISPLAY_QUEUE_VA,(void *)AOS_DISPLAY_BANK_VA,
        (void *)(AOS_DISPLAY_BANK_VA+AOS_DISPLAY_BANK_STRIDE),
        AOS_DISPLAY_BANK_STRIDE,present,0)) {
        agentos_log_info("boot_display","BOOT_DISPLAY_FAIL: metadata");
        for (;;) seL4_Yield();
    }
    volatile uint32_t *fb=(void *)AOS_BOOT_FB_VA;
    for (uint64_t i=0;i<metadata.bytes/4u;++i) fb[i]=0;
    for (;;) if (!aos_display_pump(&driver)) seL4_Yield();
}

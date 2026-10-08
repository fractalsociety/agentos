/* External renderer adapter: ordinary RAM and display queue only. */
#include <platform/boot_display.h>
#include <platform/display.h>
#include <platform/display_layout.h>
#include "agentos.h"
#include <sel4/sel4.h>
#include <string.h>
extern uint32_t fractal_boot_render(uint32_t *,size_t,const aos_boot_progress_t *);
static uint32_t pixels[640u*320u];
static aos_display_region_t *queue=(void *)AOS_DISPLAY_QUEUE_VA;
static uint32_t request_id;
void boot_screen_panic(void)
{
    agentos_log_info("boot_screen","BOOT_DISPLAY_FAIL: renderer panic");
    for (;;) seL4_Yield();
}
static int exchange(aos_display_request_t *request,aos_display_response_t *reply)
{
    request->version=1;
    request->id=++request_id;
    if (aos_display_submit(queue,request)) return -1;
    for (unsigned i=0;i<10000;++i) {
        if (!aos_display_receive(queue,reply))
            return reply->version==1 && reply->id==request_id && reply->status==0 ? 0 : -1;
        seL4_Yield();
    }
    return -1;
}
static int draw(const aos_boot_progress_t *progress)
{
    if (fractal_boot_render(pixels,sizeof(pixels)/4u,progress)) return -1;
    aos_display_response_t response;
    aos_display_request_t request={.operation=AOS_DISPLAY_BEGIN,.width=640,.height=320};
    if (exchange(&request,&response)) return -1;
    uint64_t cookie=response.cookie;
    for (uint32_t at=0;at<sizeof(pixels);) {
        uint32_t bytes=sizeof(pixels)-at;
        if (bytes>AOS_DISPLAY_CHUNK) bytes=AOS_DISPLAY_CHUNK;
        memcpy(queue->data,(uint8_t *)pixels+at,bytes);
        request=(aos_display_request_t){.operation=AOS_DISPLAY_WRITE,.cookie=cookie,.offset=at,.length=bytes};
        if (exchange(&request,&response)) return -1;
        at+=bytes;
    }
    request=(aos_display_request_t){.operation=AOS_DISPLAY_PRESENT,.cookie=cookie};
    return exchange(&request,&response);
}
void pd_main(seL4_CPtr endpoint,seL4_CPtr nameserver)
{
    (void)endpoint; (void)nameserver;
    aos_boot_progress_t current={.version=1,.stage=AOS_BOOT_STARTING,.total=1};
    if (draw(&current)) boot_screen_panic();
    for (;;) {
        aos_boot_progress_t next;
        int result=aos_boot_progress_read((void *)AOS_BOOT_PROGRESS_VA,&next);
        if (result<0) boot_screen_panic();
        if (result>0 && next.sequence!=current.sequence) {
            if (draw(&next)) boot_screen_panic();
            current=next;
            if (next.stage==AOS_BOOT_READY)
                agentos_log_info("boot_screen","BOOT_SCREEN_READY_PRESENTED");
            if (next.stage==AOS_BOOT_FAILED)
                agentos_log_info("boot_screen","BOOT_SCREEN_FAILURE_PRESENTED");
        }
        seL4_Yield();
    }
}

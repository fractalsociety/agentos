#include <platform/boot_display.h>
static uint32_t le32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t le64(const uint8_t *p)
{ return le32(p)|((uint64_t)le32(p+4)<<32); }
int aos_boot_fb_valid(const aos_boot_fb_t *m)
{
    return m && m->magic==AOS_BOOT_FB_MAGIC && m->version==1 && !m->reserved &&
        m->physical>=0x100000u && !(m->physical&4095u) &&
        m->width>=640 && m->width<=4096 && m->height>=320 && m->height<=2160 &&
        m->pitch>=m->width*4u && m->pitch<=32768 && !(m->pitch&3u) &&
        m->bytes==(uint64_t)m->pitch*m->height && m->bytes<=AOS_BOOT_FB_MAX_BYTES &&
        m->physical<=UINT64_MAX-((m->bytes+4095u)&~UINT64_C(4095));
}
int aos_boot_fb_parse(const uint8_t *extra,size_t bytes,aos_boot_fb_t *out)
{
    if (!extra || !out) return -1;
    aos_boot_fb_t result={0};
    for (size_t at=0;at<bytes;) {
        if (bytes-at<16) return -1;
        uint64_t id=le64(extra+at), len=le64(extra+at+8);
        if (len<16 || len>bytes-at) return -1;
        if (id==4) { /* SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER */
            if (result.magic || len!=38) return -1;
            const uint8_t *p=extra+at+16;
            if (p[20]!=32 || p[21]!=1) return -1;
            result=(aos_boot_fb_t){.magic=AOS_BOOT_FB_MAGIC,.version=1,
                .physical=le64(p),.pitch=le32(p+8),.width=le32(p+12),.height=le32(p+16)};
            result.bytes=(uint64_t)result.pitch*result.height;
        }
        at+=(size_t)len;
    }
    if (!aos_boot_fb_valid(&result)) return -1;
    *out=result;
    return 0;
}
int aos_boot_fb_present(const aos_boot_fb_t *m,volatile uint32_t *fb,
                       const uint32_t *p,uint32_t width,uint32_t height)
{
    if (!aos_boot_fb_valid(m) || !fb || !p || !width || !height ||
        width>m->width || height>m->height) return -1;
    uint32_t x=(m->width-width)/2u,y=(m->height-height)/2u;
    for (uint32_t row=0;row<height;++row)
        for (uint32_t col=0;col<width;++col) {
            uint32_t gray=p[row*width+col]&255u;
            fb[(y+row)*(m->pitch/4u)+x+col]=gray*0x01010101u;
        }
    return 0;
}

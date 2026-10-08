#include <platform/boot_display.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static void put32(uint8_t *p,uint32_t v) { for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p,uint64_t v) { for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i)); }
int main(void)
{
    uint8_t data[38]={0};
    put64(data,4); put64(data+8,38); put64(data+16,0xe0000000);
    put32(data+24,3200); put32(data+28,640); put32(data+32,480); data[36]=32; data[37]=1;
    aos_boot_fb_t m;
    assert(!aos_boot_fb_parse(data,sizeof(data),&m));
    assert(m.width==640 && m.pitch==3200 && m.bytes==3200*480);
    for (size_t n=0;n<38;n++) assert(aos_boot_fb_parse(data,n,&m));
    data[36]=24; assert(aos_boot_fb_parse(data,38,&m)); data[36]=32;
    put32(data+24,128); assert(aos_boot_fb_parse(data,38,&m)); put32(data+24,3200);
    uint8_t duplicate[76]; memcpy(duplicate,data,38); memcpy(duplicate+38,data,38);
    assert(aos_boot_fb_parse(duplicate,76,&m));
    assert(!aos_boot_fb_parse(data,38,&m));
    size_t words=m.bytes/4;
    uint32_t *fb=malloc((words+2)*4), pixels[4]={0x12345678,0xabcdefff,0,0x01010101};
    assert(fb); for(size_t i=0;i<words+2;i++)fb[i]=0xdeadbeef;
    assert(!aos_boot_fb_present(&m,fb+1,pixels,2,2));
    size_t first=1+239*800+319;
    assert(fb[first]==0x78787878 && fb[first+1]==0xffffffff);
    assert(fb[first+800]==0 && fb[first+801]==0x01010101);
    assert(fb[first-1]==0xdeadbeef && fb[first+2]==0xdeadbeef);
    assert(fb[0]==0xdeadbeef && fb[words+1]==0xdeadbeef);
    assert(aos_boot_fb_present(&m,fb,pixels,641,2));
    free(fb);
    aos_boot_progress_t p={.sequence=2,.version=1,.stage=AOS_BOOT_LOADING,.completed=123,.total=200}, out={0};
    assert(aos_boot_progress_read(&p,&out)==1 && out.completed==123 && out.total==200);
    p.sequence=3; assert(aos_boot_progress_read(&p,&out)==0);
    p.sequence=4; p.completed=201; assert(aos_boot_progress_read(&p,&out)==-1);
    puts("BOOT_DISPLAY_HOST_PASS");
    return 0;
}

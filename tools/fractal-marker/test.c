#define main marker_cli_main
#include "marker.c"
#undef main
#include <assert.h>
#include <platform/fractal_exchange_cycle.h>

static uint8_t media[TAIL_BYTES], saved[TAIL_BYTES];
static unsigned writes, flushes, fail_write;
static bool transport_read(void *ctx, uint64_t block, uint8_t *out) {
    (void)ctx;
    const uint64_t end = (FRACTAL_PART_LAST+1)/8-FRACTAL_XFER_MARKER_END_GUARD_BLOCKS;
    assert(block >= end-FRACTAL_XFER_BLOCK_COUNT && block < end);
    memcpy(out, media+(block-(end-FRACTAL_XFER_BLOCK_COUNT))*BLOCK, BLOCK); return true;
}
static bool transport_write(void *ctx, uint64_t block, const uint8_t *in) {
    (void)ctx;
    const uint64_t end = (FRACTAL_PART_LAST+1)/8-FRACTAL_XFER_MARKER_END_GUARD_BLOCKS;
    assert(block >= end-FRACTAL_XFER_BLOCK_COUNT && block < end);
    assert(block != end-4); /* The native side never writes the plan. */
    if (++writes == fail_write) return false;
    memcpy(media+(block-(end-FRACTAL_XFER_BLOCK_COUNT))*BLOCK, in, BLOCK); return true;
}
static bool transport_flush(void *ctx) { (void)ctx; ++flushes; return true; }
static uint32_t native_run(void) {
    uint8_t block[BLOCK];
    fractal_exchange_io_t io = { .block=block, .read_block=transport_read,
        .write_block=transport_write, .flush=transport_flush };
    writes=flushes=0; return fractal_exchange_cycle_run(&io, (FRACTAL_PART_LAST+1)/8);
}
static uint32_t crc(const uint8_t *p, size_t n) {
    uint32_t value=UINT32_MAX;
    for (size_t i=0; i<n; ++i) { value ^= p[i]; for (unsigned j=0; j<8; ++j) value=(value>>1)^((value&1)?0xedb88320u:0u); }
    return ~value;
}
static void put64(uint8_t *p, uint64_t n) { put32(p,(uint32_t)n); put32(p+4,(uint32_t)(n>>32)); }
static void gpt_header(uint8_t *h, bool backup, uint32_t table_crc) {
    memset(h,0,512); memcpy(h,"EFI PART",8); put32(h+8,0x10000); put32(h+12,92);
    put64(h+24,backup?FRACTAL_DISK_SECTORS-1:1); put64(h+32,backup?1:FRACTAL_DISK_SECTORS-1);
    put64(h+40,34); put64(h+48,FRACTAL_DISK_SECTORS-34); memset(h+56,0x37,16);
    put64(h+72,backup?FRACTAL_DISK_SECTORS-33:2); put32(h+80,128); put32(h+84,128);
    put32(h+88,table_crc); put32(h+16,crc(h,92));
}
static void fixture(const char *path) {
    int fd=open(path,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600); assert(fd>=0);
    assert(!ftruncate(fd,(off_t)(FRACTAL_DISK_SECTORS*512)));
    uint8_t table[16384]={0}, primary[512], backup[512], mbr[512]={0}; uint8_t *entry=table+7*128;
    memcpy(entry,fractal_linux_type,16); memcpy(entry+16,fractal_part_guid,16);
    put64(entry+32,FRACTAL_PART_FIRST); put64(entry+40,FRACTAL_PART_LAST);
    gpt_header(primary,false,crc(table,sizeof(table))); gpt_header(backup,true,crc(table,sizeof(table)));
    mbr[450]=0xee; mbr[510]=0x55; mbr[511]=0xaa; put32(mbr+454,1); put32(mbr+458,(uint32_t)(FRACTAL_DISK_SECTORS-1));
    assert(write_at(fd,mbr,512,0) && write_at(fd,primary,512,512) && write_at(fd,table,sizeof(table),1024));
    assert(write_at(fd,table,sizeof(table),(FRACTAL_DISK_SECTORS-33)*512) && write_at(fd,backup,512,(FRACTAL_DISK_SECTORS-1)*512));
    assert(!fsync(fd) && gpt_ok(fd)); close(fd);
}
int main(int argc, char **argv) {
    if (argc==3 && !strcmp(argv[1],"fixture")) { fixture(argv[2]); return 0; }
    static const uint8_t seed[32]={
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60};
    EVP_PKEY *key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,seed,32); assert(key);
    uint8_t plan[BLOCK], other[BLOCK], ih[32]={0x81}; make_plan(key,ih,plan); make_plan(key,ih,other); EVP_PKEY_free(key);
    assert(valid_plan(plan)); assert(memcmp(plan+16,other+16,16));
    memcpy(media+TAIL_BYTES-4*BLOCK,plan,BLOCK);
    assert(strcmp(verify(plan,media),"pass")); /* Host arming is never success. */
    assert(native_run()==2 && writes==4 && flushes==4);
    assert(!strcmp(verify(plan,media),"pass")); memcpy(saved,media,sizeof(media));
    assert(strcmp(verify(other,media),"pass")); /* Reject an old boot's result. */
    const unsigned offsets[]={TAIL_BYTES-BLOCK+16,TAIL_BYTES-BLOCK+96,TAIL_BYTES-2*BLOCK+196,
        TAIL_BYTES-3*BLOCK+999,TAIL_BYTES-FRACTAL_XFER_EVENT_OFFSET*BLOCK+16,
        TAIL_BYTES-FRACTAL_XFER_EVENT_OFFSET*BLOCK+160};
    for (unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i) {
        media[offsets[i]]^=1; assert(strcmp(verify(plan,media),"pass")); memcpy(media,saved,sizeof(media));
    }
    for (unsigned i=1;i<=4;++i) {
        memset(media,0,sizeof(media)); memcpy(media+TAIL_BYTES-4*BLOCK,plan,BLOCK); fail_write=i;
        assert(native_run()!=2); assert(strcmp(verify(plan,media),"pass"));
    }
    fail_write=0;
    memset(media,0,sizeof(media)); memcpy(media+TAIL_BYTES-4*BLOCK,plan,BLOCK);
    media[TAIL_BYTES-4*BLOCK+128]^=1; assert(native_run()==50 && writes==0 && flushes==0);
    memset(media,0,sizeof(media)); memcpy(media+TAIL_BYTES-4*BLOCK,plan,BLOCK);
    assert(native_run()==2); assert(native_run()==45 && writes==0); /* Replay rejected. */
    char dir_template[]="/tmp/fractal-marker-test-XXXXXX"; char *dir=mkdtemp(dir_template); assert(dir);
    char path[512]; snprintf(path,sizeof(path),"%s/disk.img",dir); fixture(path);
    int disk=open(path,O_RDWR); assert(disk>=0 && gpt_ok(disk));
    assert(!read_at(disk,media,sizeof(media),FRACTAL_DISK_SECTORS*512-512));
    uint8_t byte; assert(read_at(disk,&byte,1,1024+7*128+16)); byte^=1;
    assert(write_at(disk,&byte,1,1024+7*128+16)); assert(!gpt_ok(disk)); byte^=1;
    assert(write_at(disk,&byte,1,1024+7*128+16) && gpt_ok(disk));
    uint64_t backup_entry=(FRACTAL_DISK_SECTORS-33)*512+7*128+16;
    assert(read_at(disk,&byte,1,backup_entry)); byte^=1; assert(write_at(disk,&byte,1,backup_entry)); assert(!gpt_ok(disk));
    byte^=1; assert(write_at(disk,&byte,1,backup_entry) && gpt_ok(disk));
    uint8_t guard[GUARD_BYTES], guard_after[GUARD_BYTES]; memset(guard,0x53,sizeof(guard));
    uint64_t guard_offset=(FRACTAL_PART_LAST+1)*512-GUARD_BYTES;
    assert(write_at(disk,guard,sizeof(guard),guard_offset));
    assert(!fsync(disk));
    close(disk);
    disk = open(path, O_RDWR|O_DIRECT);
    assert(disk >= 0 && gpt_ok(disk)); /* 512-byte GPT reads with stack buffers. */
    assert(!read_at(disk, &byte, 1, 0));
    assert(!write_at(disk, &byte, 1, 0));
    int dirfd=run_open(dir); assert(arm_fd(disk,TAIL_OFFSET,dirfd,plan));
    assert(read_at(disk,guard_after,sizeof(guard_after),guard_offset) && !memcmp(guard,guard_after,sizeof(guard)));
    assert(read_at(disk,media,sizeof(media),TAIL_OFFSET)); assert(!memcmp(tail_block(media,4),plan,BLOCK));
    assert(zeros(media,TAIL_BYTES-4*BLOCK) && zeros(tail_block(media,3),3*BLOCK));
    assert(!arm_fd(disk,TAIL_OFFSET,dirfd,other)); /* Never overwrite occupied media. */
    assert(!arm_fd_from(disk,TAIL_OFFSET,dirfd,other,other));
    assert(!arm_fd_from(disk,TAIL_OFFSET,dirfd,plan,plan));
    char retry_path[512]; snprintf(retry_path,sizeof(retry_path),"%s/retry",dir);
    assert(!mkdir(retry_path,0700)); int retryfd=run_open(retry_path);
    for (unsigned i=0;i<FRACTAL_XFER_BLOCK_COUNT;++i) {
        if (i == FRACTAL_XFER_BLOCK_COUNT-4) continue;
        media[i*BLOCK]=0x5a;
        assert(write_at(disk,media,sizeof(media),TAIL_OFFSET));
        assert(!arm_fd_from(disk,TAIL_OFFSET,retryfd,other,plan));
        media[i*BLOCK]=0;
    }
    assert(write_at(disk,media,sizeof(media),TAIL_OFFSET));
    assert(arm_fd_from(disk,TAIL_OFFSET,retryfd,other,plan));
    assert(read_at(disk,media,sizeof(media),TAIL_OFFSET));
    assert(!memcmp(tail_block(media,4),other,BLOCK));
    assert(zeros(media,TAIL_BYTES-4*BLOCK) && zeros(tail_block(media,3),3*BLOCK));
    assert(read_at(disk,guard_after,sizeof(guard_after),guard_offset) && !memcmp(guard,guard_after,sizeof(guard)));
    close(retryfd);
    snprintf(retry_path,sizeof(retry_path),"%s/retry/tail-before.bin",dir); assert(!unlink(retry_path));
    snprintf(retry_path,sizeof(retry_path),"%s/retry",dir); assert(!rmdir(retry_path));
    close(dirfd); close(disk); assert(!unlink(path));
    snprintf(path,sizeof(path),"%s/tail-before.bin",dir); assert(!unlink(path)); assert(!rmdir(dir));
    puts("PASS: signed completion, fresh run binding, tamper/truncation, failed writes, replay, GPT, bounded arming and unconsumed-plan retry");
    return 0;
}

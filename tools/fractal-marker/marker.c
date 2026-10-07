/* One-shot host companion to the signed Fractal native-alive exchange.
 * Host writes only PLAN; only the booted native image writes completion.
 * Physical arming accepts this machine's unmounted p8 and blank exchange
 * area only. Inspection never opens the namespace for writing. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <platform/fractal_exchange.h>
#include <platform/fractal_gpt.h>
#include <platform/fractal_partition.h>
#include <platform/fractal_plan_public_key.h>

#define BLOCK FRACTAL_XFER_BLOCK_BYTES
#define TAIL_BYTES (FRACTAL_XFER_BLOCK_COUNT * BLOCK)
#define PART_BYTES ((FRACTAL_PART_LAST - FRACTAL_PART_FIRST + 1u) * 512u)
#define GUARD_BYTES (FRACTAL_XFER_MARKER_END_GUARD_BLOCKS * BLOCK)
#define TAIL_OFFSET ((FRACTAL_PART_LAST + 1u) * 512u - TAIL_BYTES - GUARD_BYTES)
#define DISK_PATH "/dev/nvme0n1"
#define PART_PATH "/dev/disk/by-partuuid/762485e0-9697-48f6-8519-a4c1e8c439e5"

static void fail(const char *s) { fprintf(stderr, "fractal-marker: %s\n", s); exit(1); }
static void need(bool ok, const char *s) { if (!ok) fail(s); }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8*i));
}
static void hash(const void *p, size_t n, uint8_t out[32]) {
    unsigned len = 0;
    need(EVP_Digest(p, n, out, &len, EVP_sha256(), NULL) == 1 && len == 32, "SHA-256 failed");
}
static bool zeros(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return false;
    return true;
}
static bool digest_matches(const uint8_t *p, size_t n, const uint8_t *expected) {
    uint8_t out[32]; hash(p, n, out); return !memcmp(out, expected, 32);
}
static void hex(const uint8_t *p, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[2*i] = digits[p[i] >> 4]; out[2*i+1] = digits[p[i] & 15]; }
    out[2*n] = 0;
}
static void uuid(const uint8_t *p, char out[37]) {
    char raw[33]; hex(p, 16, raw);
    snprintf(out, 37, "%.8s-%.4s-%.4s-%.4s-%.12s", raw, raw+8, raw+12, raw+16, raw+20);
}
static int plan_json(const uint8_t *id, char out[160]) {
    char text[37]; uuid(id, text);
    return snprintf(out, 160, "{\"run_id\":\"%s\",\"schema\":\"fractal.test-plan.v1\",\"tests\":[\"native-alive\"]}\n", text);
}
static bool valid_plan(const uint8_t plan[BLOCK]) {
    char json[160]; int n = plan_json(plan+16, json);
    if (memcmp(plan, FRACTAL_XFER_SIGNED_PLAN_MAGIC, 8) || get32(plan+8) != 2 ||
        get32(plan+12) != (uint32_t)n || memcmp(plan+192, json, (size_t)n) ||
        !zeros(plan+192+n, BLOCK-192-(size_t)n) || !digest_matches(plan, 96, plan+96) ||
        !digest_matches(plan+192, (size_t)n, plan+64)) return false;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, fractal_plan_public_key, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
              EVP_DigestVerify(ctx, plan+128, 64, plan, 96) == 1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); return ok;
}
static const uint8_t *tail_block(const uint8_t *tail, unsigned offset) {
    return tail + TAIL_BYTES - offset * BLOCK;
}
/* Returns a fixed, JSON-safe status string. Full success binds every record
 * to the independently saved, authenticated plan for this attempt. */
static const char *verify(const uint8_t plan[BLOCK], const uint8_t tail[TAIL_BYTES]) {
    if (!valid_plan(plan)) return "invalid-saved-plan";
    if (memcmp(plan, tail_block(tail, 4), BLOCK)) return "plan-mismatch";
    uint8_t prior[32] = {0}, ids[16][16]; unsigned occupied = 0, matches = 0;
    bool gap = false;
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t *event = tail_block(tail, FRACTAL_XFER_EVENT_OFFSET+i);
        if (zeros(event, BLOCK)) { gap = true; continue; }
        if (gap || memcmp(event, FRACTAL_XFER_EVENT_MAGIC, 8) || get32(event+8) != 1 ||
            get32(event+12) != 1 || memcmp(event+96, prior, 32) ||
            !digest_matches(event, 128, event+128) || !zeros(event+160, BLOCK-160)) return "invalid-event-history";
        for (unsigned j = 0; j < occupied; ++j)
            if (!memcmp(ids[j], event+16, 16)) return "duplicate-event";
        memcpy(ids[occupied++], event+16, 16);
        if (!memcmp(event+16, plan+16, 16)) {
            if (memcmp(event+32, plan+64, 32) || memcmp(event+64, plan+32, 32)) return "event-plan-mismatch";
            ++matches;
        }
        hash(event, BLOCK, prior);
    }
    if (matches != 1) return "no-matching-native-event";
    const uint8_t *done = tail_block(tail, 1), *result = tail_block(tail, 2), *witness = tail_block(tail, 3);
    if (memcmp(done, FRACTAL_XFER_COMPLETE_MAGIC, 8) || get32(done+8) != 1 || get32(done+12) ||
        memcmp(done+16, plan+16, 16) || memcmp(done+64, plan+64, 32) ||
        !digest_matches(done, 96, done+96) || !zeros(done+128, BLOCK-128)) return "no-valid-completion";
    if (!digest_matches(result, BLOCK, done+32) || memcmp(result, FRACTAL_XFER_RESULT_MAGIC, 8) ||
        get32(result+8) != 1 || get32(result+12) || memcmp(result+16, plan+16, 16) ||
        memcmp(result+32, plan+64, 32) || memcmp(result+64, plan+32, 32) ||
        !digest_matches(result, 164, result+164)) return "invalid-result";
    for (unsigned i = 0; i < BLOCK; ++i)
        if (witness[i] != (uint8_t)(i ^ plan[16+i%16] ^ 0xa5)) return "invalid-witness";
    if (!digest_matches(witness, BLOCK, result+96)) return "witness-hash-mismatch";
    uint32_t len = get32(result+128);
    if (!len || len >= BLOCK-196 || !digest_matches(result+196, len, result+132) ||
        !zeros(result+196+len, BLOCK-196-len)) return "invalid-result-json";
    char id[37], image[65], whash[65], expected[1024];
    uuid(plan+16, id); hex(plan+32, 32, image); hex(result+96, 32, whash);
    int expected_len = snprintf(expected, sizeof(expected),
        "{\"agentos_image_hash\":\"%s\",\"artifacts_hash\":\"%s\","
        "\"bytes_communicated\":24576,\"energy_estimate_j\":null,"
        "\"failed_tasks\":[],\"latency_ms\":null,\"peak_ram_bytes\":null,"
        "\"run_id\":\"%s\",\"schema\":\"fractal.final.v1\","
        "\"status\":\"pass\",\"system_one_decisions\":0,"
        "\"system_two_calls\":0,\"tokens_in\":0,\"tokens_out\":0,"
        "\"tool_calls\":0,\"verified_tasks\":[\"native-alive\"]}\n", image, whash, id);
    if (expected_len < 0 || len != (uint32_t)expected_len || memcmp(expected, result+196, len)) return "unexpected-result-json";
    return "pass";
}
static bool read_raw(int fd, void *buffer, size_t n, uint64_t offset) {
    uint8_t *p = buffer;
    while (n) { ssize_t got = pread(fd, p, n, (off_t)offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        p += got; n -= (size_t)got; offset += (uint64_t)got;
    } return true;
}
static bool write_raw(int fd, const void *buffer, size_t n, uint64_t offset) {
    const uint8_t *p = buffer;
    while (n) { ssize_t put = pwrite(fd, p, n, (off_t)offset);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) return false;
        p += put; n -= (size_t)put; offset += (uint64_t)put;
    } return true;
}
/* Namespace and partition aliases have independent Linux page caches. Use
 * direct I/O for physical media; bounce stack buffers to aligned storage.
 * Never fall back to cached data when the direct read fails. */
static bool media_io(int fd, void *buffer, size_t n, uint64_t offset, bool writing) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return false;
    if (!(flags & O_DIRECT))
        return writing ? write_raw(fd, buffer, n, offset) : read_raw(fd, buffer, n, offset);
    if (!n || (n & 511u) || (offset & 511u)) return false;
    void *aligned = NULL;
    if (posix_memalign(&aligned, 4096, n)) return false;
    if (writing) memcpy(aligned, buffer, n);
    bool ok = writing ? write_raw(fd, aligned, n, offset) : read_raw(fd, aligned, n, offset);
    if (ok && !writing) memcpy(buffer, aligned, n);
    free(aligned);
    return ok;
}
static bool read_at(int fd, void *buffer, size_t n, uint64_t offset) {
    return media_io(fd, buffer, n, offset, false);
}
static bool write_at(int fd, const void *buffer, size_t n, uint64_t offset) {
    return media_io(fd, (void *)buffer, n, offset, true);
}
static int run_open(const char *path) {
    int fd = open(path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    need(fd >= 0, "cannot open run directory"); return fd;
}
static void save_new(int dir, const char *name, const void *p, size_t n) {
    int fd = openat(dir, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0644);
    need(fd >= 0, "receipt already exists or cannot be created");
    need(write_at(fd, p, n, 0) && fsync(fd) == 0, "receipt write/flush failed");
    need(close(fd) == 0 && fsync(dir) == 0, "receipt close/directory flush failed");
}
static void load_plan(int dir, uint8_t plan[BLOCK]) {
    int fd = openat(dir, "plan.bin", O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat st;
    need(fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size == BLOCK &&
         read_at(fd, plan, BLOCK, 0), "cannot read exact saved plan");
    close(fd); need(valid_plan(plan), "saved plan authentication failed");
}
static void make_plan(EVP_PKEY *key, const uint8_t image_hash[32], uint8_t plan[BLOCK]) {
    uint8_t pub[32]; size_t pub_len = sizeof(pub), sig_len = 64;
    need(EVP_PKEY_get_raw_public_key(key, pub, &pub_len) == 1 && pub_len == 32 &&
         !memcmp(pub, fractal_plan_public_key, 32), "signing key differs from native image key");
    memset(plan, 0, BLOCK); memcpy(plan, FRACTAL_XFER_SIGNED_PLAN_MAGIC, 8); put32(plan+8, 2);
    need(RAND_bytes(plan+16, 16) == 1, "random run ID failed");
    plan[22] = (plan[22] & 15) | 0x40; plan[24] = (plan[24] & 63) | 0x80;
    memcpy(plan+32, image_hash, 32);
    char json[160]; int n = plan_json(plan+16, json);
    put32(plan+12, (uint32_t)n); memcpy(plan+192, json, (size_t)n);
    hash(plan+192, (size_t)n, plan+64); hash(plan, 96, plan+96);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    need(ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
         EVP_DigestSign(ctx, plan+128, &sig_len, plan, 96) == 1 && sig_len == 64, "plan signing failed");
    EVP_MD_CTX_free(ctx); need(valid_plan(plan), "plan self-verification failed");
}
static void prepare(const char *image_path, const char *key_path, const char *run) {
    int image = open(image_path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat st;
    need(image >= 0 && !fstat(image, &st) && S_ISREG(st.st_mode) && st.st_size > 0, "invalid root-task image");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); uint8_t buffer[16384], image_hash[32], plan[BLOCK]; unsigned len;
    need(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1, "image hash init failed");
    for (;;) { ssize_t n = read(image, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        need(n >= 0, "image read failed"); if (!n) break;
        need(EVP_DigestUpdate(ctx, buffer, (size_t)n) == 1, "image hash update failed");
    }
    close(image); need(EVP_DigestFinal_ex(ctx, image_hash, &len) == 1 && len == 32, "image hash failed"); EVP_MD_CTX_free(ctx);
    FILE *file = fopen(key_path, "r"); need(file != NULL, "cannot open signing key");
    EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL); fclose(file);
    need(key != NULL, "cannot decode signing key"); make_plan(key, image_hash, plan); EVP_PKEY_free(key);
    need(mkdir(run, 0755) == 0, "run directory must be new"); int dir = run_open(run);
    save_new(dir, "plan.bin", plan, BLOCK);
    char id[37], ih[65], json[512]; uuid(plan+16, id); hex(image_hash, 32, ih);
    int n = snprintf(json, sizeof(json), "{\"schema\":\"fractal.boot-marker-plan.v1\",\"run_id\":\"%s\",\"root_task_sha256\":\"%s\",\"status\":\"prepared-not-armed\"}\n", id, ih);
    save_new(dir, "plan.json", json, (size_t)n); close(dir); fputs(json, stdout);
}
static bool gpt_ok(int fd) {
    uint8_t header[512], entries[4096]; fractal_gpt_guard_t primary, backup;
    if (!read_at(fd, header, 512, 0) || header[510] != 0x55 || header[511] != 0xaa || header[450] != 0xee ||
        !read_at(fd, header, 512, 512) || !fractal_gpt_begin(&primary, header, FRACTAL_DISK_SECTORS,
            fractal_part_guid, fractal_linux_type, FRACTAL_PART_FIRST, FRACTAL_PART_LAST)) return false;
    for (unsigned i = 0; i < 4; ++i)
        if (!read_at(fd, entries, 4096, (2u+8u*i)*512u) || !fractal_gpt_feed(&primary, entries)) return false;
    if (!fractal_gpt_finish(&primary) || !read_at(fd, header, 512, (FRACTAL_DISK_SECTORS-1)*512u) ||
        !fractal_gpt_begin_backup(&backup, header, &primary)) return false;
    for (unsigned i = 0; i < 4; ++i)
        if (!read_at(fd, entries, 4096, (FRACTAL_DISK_SECTORS-33+8*i)*512u) || !fractal_gpt_feed(&backup, entries)) return false;
    return fractal_gpt_finish(&backup);
}
static uint64_t number_file(const char *path) {
    FILE *f = fopen(path, "r"); long long n = 0;
    need(f && fscanf(f, "%lli", &n) == 1 && n >= 0, "cannot read physical device identity"); fclose(f); return (uint64_t)n;
}
static int disk_open(const char *path, bool image, bool writing) {
    int fd = open(path, (writing ? O_RDWR : O_RDONLY)|O_NOFOLLOW|O_CLOEXEC|
                       (image ? 0 : O_DIRECT));
    struct stat st; uint64_t size = 0; unsigned sector = 0;
    need(fd >= 0 && !fstat(fd, &st), "cannot open namespace");
    if (image) { need(S_ISREG(st.st_mode), "image mode requires a regular file"); size = (uint64_t)st.st_size; }
    else {
        need(S_ISBLK(st.st_mode) && ioctl(fd, BLKGETSIZE64, &size) == 0 &&
             ioctl(fd, BLKSSZGET, &sector) == 0 && sector == 512, "wrong physical namespace format");
        char link[128], resolved[4096]; snprintf(link, sizeof(link), "/sys/dev/block/%u:%u", major(st.st_rdev), minor(st.st_rdev));
        need(realpath(link, resolved) && strstr(resolved, "/0000:81:00.0/nvme/nvme0/nvme0n1") &&
             !strcmp(strrchr(resolved, '/'), "/nvme0n1"), "wrong physical namespace path");
        need(number_file("/sys/bus/pci/devices/0000:81:00.0/vendor") == 0x144d &&
             number_file("/sys/bus/pci/devices/0000:81:00.0/device") == 0xa80d, "wrong NVMe controller");
    }
    need(size == FRACTAL_DISK_SECTORS*512u && gpt_ok(fd), "namespace size or primary/backup GPT mismatch");
    return fd;
}
static bool arm_fd_from(int fd, uint64_t tail_offset, int dir, const uint8_t plan[BLOCK],
                        const uint8_t *previous) {
    uint8_t before[TAIL_BYTES], after[TAIL_BYTES];
    if (!valid_plan(plan) || !read_at(fd, before, sizeof(before), tail_offset)) return false;
    if (previous) {
        /* An explicit retry replaces only a matching, unconsumed plan. Any
         * event, partial result, or unknown byte must be investigated first. */
        if (!valid_plan(previous) || !memcmp(plan+16, previous+16, 16) ||
            memcmp(tail_block(before, 4), previous, BLOCK) ||
            !zeros(before, TAIL_BYTES-4*BLOCK) || !zeros(tail_block(before, 3), 3*BLOCK)) return false;
    } else if (!zeros(before, sizeof(before))) return false;
    save_new(dir, "tail-before.bin", before, sizeof(before));
    if (!write_at(fd, plan, BLOCK, tail_offset+TAIL_BYTES-4*BLOCK) || fsync(fd) ||
        !read_at(fd, after, sizeof(after), tail_offset)) return false;
    memcpy(before+TAIL_BYTES-4*BLOCK, plan, BLOCK);
    return !memcmp(before, after, sizeof(before));
}
static bool arm_fd(int fd, uint64_t tail_offset, int dir, const uint8_t plan[BLOCK]) {
    return arm_fd_from(fd, tail_offset, dir, plan, NULL);
}
static void arm(const char *path, bool image, const char *run, const char *previous_run) {
    uint8_t plan[BLOCK]; int dir = run_open(run); load_plan(dir, plan);
    uint8_t previous[BLOCK];
    if (previous_run) { int old = run_open(previous_run); load_plan(old, previous); close(old); }
    int disk = disk_open(path, image, image), out = disk; uint64_t offset = TAIL_OFFSET;
    if (!image) {
        out = open(PART_PATH, O_RDWR|O_EXCL|O_CLOEXEC|O_DIRECT); struct stat st; uint64_t bytes = 0;
        need(out >= 0 && !fstat(out, &st) && S_ISBLK(st.st_mode) &&
             ioctl(out, BLKGETSIZE64, &bytes) == 0 && bytes == PART_BYTES, "Fractal partition busy or wrong size");
        char link[128], resolved[4096]; snprintf(link, sizeof(link), "/sys/dev/block/%u:%u", major(st.st_rdev), minor(st.st_rdev));
        need(realpath(link, resolved) && strstr(resolved, "/0000:81:00.0/nvme/nvme0/nvme0n1/nvme0n1p8") &&
             !strcmp(strrchr(resolved, '/'), "/nvme0n1p8") &&
             number_file("/sys/class/block/nvme0n1p8/start") == FRACTAL_PART_FIRST &&
             number_file("/sys/class/block/nvme0n1p8/size") == PART_BYTES/512, "wrong partition mapping");
        offset = PART_BYTES-TAIL_BYTES-GUARD_BYTES;
    }
    need(flock(out, LOCK_EX|LOCK_NB) == 0, "marker area locked");
    need(previous_run ? arm_fd_from(out, offset, dir, plan, previous) : arm_fd(out, offset, dir, plan),
         "arming failed: expected blank media or the exact unconsumed previous plan");
    static const char receipt[] = "{\"schema\":\"fractal.boot-marker-arm.v1\",\"status\":\"plan-flushed-and-read-back\",\"host_bytes_written\":4096,\"native_completion_written_by_host\":false}\n";
    save_new(dir, "armed.json", receipt, sizeof(receipt)-1);
    if (out != disk) close(out);
    close(disk); close(dir); fputs(receipt, stdout);
}
static int inspect(const char *path, bool image, const char *run, bool collect) {
    uint8_t plan[BLOCK], tail[TAIL_BYTES]; int dir = run_open(run); load_plan(dir, plan);
    int disk = disk_open(path, image, false); need(read_at(disk, tail, sizeof(tail), TAIL_OFFSET), "cannot read marker area");
    close(disk); const char *status = verify(plan, tail); bool pass = !strcmp(status, "pass");
    char id[37], boot[37] = {0}, json[512]; uuid(plan+16, id);
    int bootfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY|O_CLOEXEC);
    need(bootfd >= 0 && read_at(bootfd, boot, 36, 0), "cannot read Linux boot ID"); close(bootfd);
    for (unsigned i = 0; i < 36; ++i)
        need((boot[i] >= '0' && boot[i] <= '9') || (boot[i] >= 'a' && boot[i] <= 'f') || boot[i] == '-', "invalid Linux boot ID");
    int n = snprintf(json, sizeof(json), "{\"schema\":\"fractal.boot-marker-result.v1\",\"run_id\":\"%s\",\"linux_boot_id\":\"%s\",\"status\":\"%s\",\"matching_native_completion\":%s,\"medium\":\"%s\"}\n", id, boot, status, pass ? "true" : "false", image ? "image" : "physical-nvme");
    if (collect) {
        char name[80]; snprintf(name, sizeof(name), "return-%s.bin", boot); save_new(dir, name, tail, sizeof(tail));
        snprintf(name, sizeof(name), "return-%s.json", boot); save_new(dir, name, json, (size_t)n);
        if (pass) save_new(dir, "complete.json", json, (size_t)n);
    }
    close(dir); fputs(json, stdout);
    return pass ? 0 : 2;
}
int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "prepare")) { prepare(argv[2], argv[3], argv[4]); return 0; }
    if (argc == 3 && !strcmp(argv[1], "arm")) { arm(DISK_PATH, false, argv[2], NULL); return 0; }
    if (argc == 4 && !strcmp(argv[1], "retry")) { arm(DISK_PATH, false, argv[3], argv[2]); return 0; }
    if (argc == 3 && !strcmp(argv[1], "inspect")) return inspect(DISK_PATH, false, argv[2], false);
    if (argc == 3 && !strcmp(argv[1], "collect")) return inspect(DISK_PATH, false, argv[2], true);
    if (argc == 4 && !strcmp(argv[1], "arm-image")) { arm(argv[2], true, argv[3], NULL); return 0; }
    if (argc == 5 && !strcmp(argv[1], "retry-image")) { arm(argv[2], true, argv[4], argv[3]); return 0; }
    if (argc == 4 && !strcmp(argv[1], "inspect-image")) return inspect(argv[2], true, argv[3], false);
    if (argc == 4 && !strcmp(argv[1], "collect-image")) return inspect(argv[2], true, argv[3], true);
    fputs("Usage: fractal-marker prepare ROOT_TASK_ELF PRIVATE_KEY_PEM NEW_RUN_DIR\n"
          "       fractal-marker arm RUN_DIR\n       fractal-marker inspect RUN_DIR\n       fractal-marker collect RUN_DIR\n"
          "       fractal-marker retry PREVIOUS_RUN_DIR NEW_RUN_DIR\n"
          "       fractal-marker arm-image REGULAR_DISK_IMAGE RUN_DIR\n"
          "       fractal-marker inspect-image REGULAR_DISK_IMAGE RUN_DIR\n"
          "       fractal-marker collect-image REGULAR_DISK_IMAGE RUN_DIR\n"
          "       fractal-marker retry-image REGULAR_DISK_IMAGE PREVIOUS_RUN_DIR NEW_RUN_DIR\n"
          "Physical arm writes one signed plan to a blank, GPT-validated Fractal p8 tail.\n"
          "It does not install a boot image, set BootNext, or reboot.\n"
          "Inspect is read-only; exit 2 means no verified completion for this run.\n"
          "Collect also saves raw marker bytes and a receipt in RUN_DIR once per Linux boot.\n", stderr);
    return 1;
}

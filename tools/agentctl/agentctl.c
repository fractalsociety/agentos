/*
 * agentctl — FractalOS Command-and-Control reference consumer
 *
 * Host-side CLI. Connects to cc_pd's Unix socket bridge, sends one binary
 * CC frame, prints structured output, and exits. No interactive UI.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef AGENTCTL_MESH_HELPER_PATH
#define AGENTCTL_MESH_HELPER_PATH "/usr/local/libexec/agentctl-mesh"
#endif

#include "contracts/cc_contract.h"
#include "contracts/guest_contract.h"

#define AGENTCTL_VERSION "0.2.0"
#define DEFAULT_CC_SOCK "build/cc_pd.sock"
#define MY_BADGE 0xA6E70001u
#define CC_WIRE_SHMEM_SIZE 4096u

typedef struct {
    uint32_t opcode;
    uint32_t mr[3];
    uint8_t shmem[CC_WIRE_SHMEM_SIZE];
} cc_req_wire_t;

typedef struct {
    uint32_t mr[4];
    uint8_t shmem[CC_WIRE_SHMEM_SIZE];
} cc_reply_wire_t;

static const char *g_sock_path = DEFAULT_CC_SOCK;

static void usage(FILE *out)
{
    fprintf(out,
            "agentctl v%s\n"
            "Usage: agentctl [--socket PATH] [--batch] COMMAND [ARGS...]\n\n"
            "Commands:\n"
            "  list-guests\n"
            "  guest-status HANDLE\n"
            "  list-devices TYPE [MAX]\n"
            "  device-status TYPE HANDLE\n"
            "  polecats | list-polecats\n"
            "  log-stream SLOT PD_ID\n"
            "  fb-attach GUEST_HANDLE FB_HANDLE\n"
            "  send-input GUEST_HANDLE KEYCODE\n"
            "  suspend GUEST_HANDLE\n"
            "  resume GUEST_HANDLE\n"
            "  destroy GUEST_HANDLE [REASON]\n"
            "  snapshot GUEST_HANDLE\n"
            "  restore GUEST_HANDLE SNAP_LO SNAP_HI\n"
            "  trace-start [FLAGS]\n"
            "  trace-stop\n"
            "  trace-query\n"
            "  trace-dump [MAX_EVENTS]\n"
            "  agent-run [--caps MASK] [--max-steps N] [--require-test] PROMPT\n"
            "  agent-run-file [--caps MASK] [--max-steps N] [--require-test] PATH\n"
            "  mesh [--url URL] status|nodes|users|enroll-key|expire-node ...\n"
            "  connect\n"
            "  status SESSION_ID\n"
            "  raw OPCODE [MR1 [MR2 [MR3]]]\n\n"
            "Socket defaults to $CC_PD_SOCK, then %s.\n",
            AGENTCTL_VERSION, DEFAULT_CC_SOCK);
}

static uint32_t parse_u32(const char *s, const char *name)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0' || v > UINT32_MAX) {
        fprintf(stderr, "agentctl: invalid %s: %s\n", name, s);
        exit(2);
    }
    return (uint32_t)v;
}

static int connect_cc(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("agentctl: socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g_sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "agentctl: socket path too long: %s\n", g_sock_path);
        close(fd);
        return -1;
    }
    strcpy(addr.sun_path, g_sock_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "agentctl: cannot connect to %s: %s\n",
                g_sock_path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static bool write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += (size_t)w;
        n -= (size_t)w;
    }
    return true;
}

static bool read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += (size_t)r;
        n -= (size_t)r;
    }
    return true;
}

static bool cc_call(uint32_t opcode, uint32_t mr1, uint32_t mr2, uint32_t mr3,
                    const void *shmem, size_t shmem_len, cc_reply_wire_t *reply)
{
    cc_req_wire_t req;
    memset(&req, 0, sizeof(req));
    memset(reply, 0, sizeof(*reply));
    req.opcode = opcode;
    req.mr[0] = mr1;
    req.mr[1] = mr2;
    req.mr[2] = mr3;
    if (shmem && shmem_len > 0) {
        if (shmem_len > sizeof(req.shmem)) shmem_len = sizeof(req.shmem);
        memcpy(req.shmem, shmem, shmem_len);
    }

    int fd = connect_cc();
    if (fd < 0) return false;
    bool ok = write_full(fd, &req, sizeof(req)) &&
              read_full(fd, reply, sizeof(*reply));
    close(fd);
    if (!ok) {
        fprintf(stderr, "agentctl: CC frame I/O failed\n");
    }
    return ok;
}

static void print_raw_reply(const cc_reply_wire_t *r)
{
    printf("{\"mr\":[%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 "]}\n",
           r->mr[0], r->mr[1], r->mr[2], r->mr[3]);
}

static int cmd_connect(void)
{
    cc_reply_wire_t r;
    if (!cc_call(MSG_CC_CONNECT, MY_BADGE, CC_CONNECT_FLAG_BINARY, 0,
                 NULL, 0, &r)) return 1;
    printf("{\"ok\":%" PRIu32 ",\"session_id\":%" PRIu32 "}\n",
           r.mr[0], r.mr[1]);
    return r.mr[0] == CC_OK ? 0 : 1;
}

static int cmd_status(int argc, char **argv)
{
    if (argc < 1) return 2;
    cc_reply_wire_t r;
    uint32_t sid = parse_u32(argv[0], "session_id");
    if (!cc_call(MSG_CC_STATUS, sid, 0, 0, NULL, 0, &r)) return 1;
    printf("{\"ok\":%" PRIu32 ",\"state\":%" PRIu32
           ",\"pending_responses\":%" PRIu32
           ",\"ticks_since_active\":%" PRIu32 "}\n",
           r.mr[0], r.mr[1], r.mr[2], r.mr[3]);
    return r.mr[0] == CC_OK ? 0 : 1;
}

static int cmd_list_guests(void)
{
    cc_reply_wire_t r;
    if (!cc_call(MSG_CC_LIST_GUESTS, 64, 0, 0, NULL, 0, &r)) return 1;
    uint32_t count = r.mr[0];
    size_t max = sizeof(r.shmem) / sizeof(cc_guest_info_t);
    if (count > max) count = (uint32_t)max;
    cc_guest_info_t *g = (cc_guest_info_t *)r.shmem;
    printf("{\"count\":%" PRIu32 ",\"guests\":[", count);
    for (uint32_t i = 0; i < count; i++) {
        if (i) printf(",");
        printf("{\"guest_handle\":%" PRIu32 ",\"state\":%" PRIu32
               ",\"os_type\":%" PRIu32 ",\"arch\":%" PRIu32 "}",
               g[i].guest_handle, g[i].state, g[i].os_type, g[i].arch);
    }
    printf("]}\n");
    return 0;
}

static int cmd_guest_status(int argc, char **argv)
{
    if (argc < 1) return 2;
    cc_reply_wire_t r;
    uint32_t handle = parse_u32(argv[0], "guest_handle");
    if (!cc_call(MSG_CC_GUEST_STATUS, handle, 0, 0, NULL, 0, &r)) return 1;
    printf("{\"ok\":%" PRIu32, r.mr[0]);
    if (r.mr[0] == CC_OK) {
        cc_guest_status_t *s = (cc_guest_status_t *)r.shmem;
        printf(",\"guest_handle\":%" PRIu32 ",\"state\":%" PRIu32
               ",\"os_type\":%" PRIu32 ",\"arch\":%" PRIu32
               ",\"device_flags\":%" PRIu32,
               s->guest_handle, s->state, s->os_type, s->arch, s->device_flags);
    }
    printf("}\n");
    return r.mr[0] == CC_OK ? 0 : 1;
}

static int cmd_list_devices(int argc, char **argv)
{
    if (argc < 1) return 2;
    uint32_t dev_type = parse_u32(argv[0], "dev_type");
    uint32_t max_entries = argc > 1 ? parse_u32(argv[1], "max") : 64u;
    cc_reply_wire_t r;
    if (!cc_call(MSG_CC_LIST_DEVICES, dev_type, max_entries, 0, NULL, 0, &r)) {
        return 1;
    }
    uint32_t count = r.mr[0];
    size_t max = sizeof(r.shmem) / sizeof(cc_device_info_t);
    if (count > max) count = (uint32_t)max;
    cc_device_info_t *d = (cc_device_info_t *)r.shmem;
    printf("{\"count\":%" PRIu32 ",\"devices\":[", count);
    for (uint32_t i = 0; i < count; i++) {
        if (i) printf(",");
        printf("{\"dev_type\":%" PRIu32 ",\"dev_handle\":%" PRIu32
               ",\"state\":%" PRIu32 "}",
               d[i].dev_type, d[i].dev_handle, d[i].state);
    }
    printf("]}\n");
    return 0;
}

static int cmd_simple(uint32_t opcode, uint32_t mr1, uint32_t mr2, uint32_t mr3)
{
    cc_reply_wire_t r;
    if (!cc_call(opcode, mr1, mr2, mr3, NULL, 0, &r)) return 1;
    print_raw_reply(&r);
    return r.mr[0] == CC_OK ? 0 : 1;
}

static int cmd_send_input(int argc, char **argv)
{
    if (argc < 2) return 2;
    uint32_t guest = parse_u32(argv[0], "guest_handle");
    cc_input_event_t event;
    memset(&event, 0, sizeof(event));
    event.event_type = CC_INPUT_KEY_DOWN;
    event.keycode = parse_u32(argv[1], "keycode");

    cc_reply_wire_t r;
    if (!cc_call(MSG_CC_SEND_INPUT, guest, 0, 0, &event, sizeof(event), &r)) {
        return 1;
    }
    printf("{\"ok\":%" PRIu32 "}\n", r.mr[0]);
    return r.mr[0] == CC_OK ? 0 : 1;
}

static int cmd_trace_dump(int argc, char **argv)
{
    uint32_t max_events = argc > 0 ? parse_u32(argv[0], "max_events") : 0u;
    cc_reply_wire_t r;
    if (!cc_call(MSG_CC_TRACE_DUMP, max_events, 0, 0, NULL, 0, &r)) return 1;
    uint32_t count = r.mr[1];
    size_t max = sizeof(r.shmem) / sizeof(cc_trace_entry_t);
    if (count > max) count = (uint32_t)max;
    cc_trace_entry_t *e = (cc_trace_entry_t *)r.shmem;
    printf("{\"ok\":%" PRIu32 ",\"events_written\":%" PRIu32
           ",\"bytes_written\":%" PRIu32 ",\"overflow_count\":%" PRIu32
           ",\"events\":[",
           r.mr[0], count, r.mr[2], r.mr[3]);
    for (uint32_t i = 0; i < count; i++) {
        if (i) printf(",");
        printf("{\"timestamp_ns\":%" PRIu64 ",\"from_pd\":%u"
               ",\"to_pd\":%u,\"channel\":%u"
               ",\"opcode\":%u,\"seq_lo\":%u}",
               e[i].timestamp_ns, (unsigned)e[i].from_pd,
               (unsigned)e[i].to_pd, (unsigned)e[i].channel,
               (unsigned)e[i].opcode, (unsigned)e[i].seq_lo);
    }
    printf("]}\n");
    return r.mr[0] == CC_OK ? 0 : 1;
}

static void print_json_bytes(const uint8_t *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    putchar('"');
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar((int)c);
        } else if (c == '\n') {
            fputs("\\n", stdout);
        } else if (c == '\r') {
            fputs("\\r", stdout);
        } else if (c == '\t') {
            fputs("\\t", stdout);
        } else if (c < 0x20u) {
            fputs("\\u00", stdout);
            putchar(hex[c >> 4u]);
            putchar(hex[c & 0x0fu]);
        } else {
            putchar((int)c);
        }
    }
    putchar('"');
}

static bool read_prompt_file(const char *path, uint8_t *dst, size_t cap,
                             size_t *len)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "agentctl: cannot open prompt file %s: %s\n",
                path, strerror(errno));
        return false;
    }
    size_t n = fread(dst, 1u, cap, file);
    int extra = fgetc(file);
    bool ok = !ferror(file) && extra == EOF;
    fclose(file);
    if (!ok) {
        fprintf(stderr, "agentctl: prompt file exceeds %u bytes\n",
                (unsigned)cap);
        return false;
    }
    *len = n;
    return n != 0u;
}

static int cmd_agent_run(int argc, char **argv, bool from_file)
{
    uint32_t caps = HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC;
    uint32_t flags = HARNESS_TASK_ALLOW_PATCH;
    uint32_t max_steps = 16u;
    int i = 0;
    while (i < argc && strncmp(argv[i], "--", 2u) == 0) {
        if (strcmp(argv[i], "--caps") == 0 && i + 1 < argc) {
            caps = parse_u32(argv[i + 1], "caps");
            i += 2;
        } else if (strcmp(argv[i], "--max-steps") == 0 && i + 1 < argc) {
            max_steps = parse_u32(argv[i + 1], "max_steps");
            i += 2;
        } else if (strcmp(argv[i], "--require-test") == 0) {
            flags |= HARNESS_TASK_REQUIRE_TEST;
            i++;
        } else if (strcmp(argv[i], "--no-patch") == 0) {
            flags &= ~HARNESS_TASK_ALLOW_PATCH;
            i++;
        } else {
            fprintf(stderr, "agentctl: invalid agent-run option: %s\n", argv[i]);
            return 2;
        }
    }
    if (i + 1 != argc || max_steps == 0u) return 2;

    uint8_t frame[CC_MAX_CMD_BYTES];
    memset(frame, 0, sizeof(frame));
    uint8_t *prompt = frame + sizeof(struct cc_agent_run_request);
    size_t prompt_len = 0u;
    if (from_file) {
        if (!read_prompt_file(argv[i], prompt, CC_AGENT_PROMPT_MAX,
                              &prompt_len))
            return 1;
    } else {
        prompt_len = strlen(argv[i]);
        if (prompt_len == 0u || prompt_len > CC_AGENT_PROMPT_MAX) {
            fprintf(stderr, "agentctl: prompt must be 1..%u bytes\n",
                    (unsigned)CC_AGENT_PROMPT_MAX);
            return 2;
        }
        memcpy(prompt, argv[i], prompt_len);
    }

    struct cc_agent_run_request request = {
        .interface_version = CC_AGENT_INTERFACE_VERSION,
        .required_caps = caps,
        .task_flags = flags,
        .max_steps = max_steps,
        .prompt_len = (uint32_t)prompt_len,
    };
    memcpy(frame, &request, sizeof(request));

    cc_reply_wire_t reply;
    if (!cc_call(MSG_CC_AGENT_RUN, 0u, 0u, 0u, frame,
                 sizeof(request) + prompt_len, &reply))
        return 1;
    if (reply.mr[0] != CC_OK) {
        printf("{\"ok\":%" PRIu32 ",\"task_id\":%" PRIu32
               ",\"transport_error\":true}\n", reply.mr[0], reply.mr[1]);
        return 1;
    }
    if (reply.mr[2] > CC_AGENT_RESULT_MAX) {
        fprintf(stderr, "agentctl: FractalOS returned an oversized result\n");
        return 1;
    }
    struct cc_agent_run_result result;
    memcpy(&result, reply.shmem, sizeof(result));
    if (result.interface_version != CC_AGENT_INTERFACE_VERSION
        || result.metrics.task_id != reply.mr[1]
        || result.metrics.result_len != reply.mr[2]) {
        fprintf(stderr, "agentctl: invalid FractalOS native-task response\n");
        return 1;
    }

    printf("{\"ok\":%" PRIu32 ",\"task_id\":%" PRIu32
           ",\"state\":%" PRIu32 ",\"result\":",
           result.metrics.status, result.metrics.task_id, result.metrics.state);
    print_json_bytes(reply.shmem + sizeof(result), result.metrics.result_len);
    printf(",\"metrics\":{\"model_calls\":%" PRIu32
           ",\"tool_calls\":%" PRIu32
           ",\"memory_ops\":%" PRIu32
           ",\"exec_calls\":%" PRIu32
           ",\"tokens_in\":%" PRIu32
           ",\"tokens_out\":%" PRIu32
           ",\"verification_exit_code\":%" PRId32
           ",\"used_caps\":%" PRIu32 "},\"resources\":{"
           "\"private_committed_bytes\":%" PRIu32
           ",\"private_limit_bytes\":%" PRIu32
           ",\"shared_mapped_bytes\":%" PRIu32
           ",\"target_low_bytes\":%" PRIu32
           ",\"target_high_bytes\":%" PRIu32
           ",\"shared_components\":%" PRIu32 "}}\n",
           result.metrics.model_calls, result.metrics.tool_calls,
           result.metrics.memory_ops, result.metrics.exec_calls,
           result.metrics.tokens_in, result.metrics.tokens_out,
           result.metrics.verification_exit_code, result.metrics.used_caps,
           result.resources.private_committed_bytes,
           result.resources.private_limit_bytes,
           result.resources.shared_mapped_bytes,
           result.resources.target_low_bytes,
           result.resources.target_high_bytes,
           result.resources.shared_components);
    return result.metrics.status == HARNESS_OK ? 0 : 1;
}

static int cmd_mesh(int argc, char **argv)
{
    const char *helper = getenv("AGENTCTL_MESH_HELPER");
    if (!helper || !*helper) {
        if (access(AGENTCTL_MESH_HELPER_PATH, X_OK) == 0) {
            helper = AGENTCTL_MESH_HELPER_PATH;
        } else if (access("tools/agentctl/agentctl-mesh", X_OK) == 0) {
            helper = "tools/agentctl/agentctl-mesh";
        } else {
            helper = "agentctl-mesh";
        }
    }
    char **child_argv = calloc((size_t)argc + 2u, sizeof(char *));
    if (!child_argv) {
        fprintf(stderr, "agentctl: cannot allocate mesh command arguments\n");
        return 1;
    }
    child_argv[0] = (char *)helper;
    for (int j = 0; j < argc; j++) child_argv[j + 1] = argv[j];
    execvp(helper, child_argv);
    fprintf(stderr, "agentctl: cannot execute mesh helper %s: %s\n",
            helper, strerror(errno));
    free(child_argv);
    return 1;
}

int main(int argc, char **argv)
{
    const char *env_sock = getenv("CC_PD_SOCK");
    if (env_sock && *env_sock) g_sock_path = env_sock;

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(argv[i], "--socket") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "agentctl: --socket requires PATH\n");
                return 2;
            }
            g_sock_path = argv[i++];
        } else if (strcmp(argv[i], "--batch") == 0) {
            i++;
        } else {
            break;
        }
    }

    if (i >= argc) {
        usage(stderr);
        return 2;
    }

    const char *cmd = argv[i++];
    int n = argc - i;
    char **args = &argv[i];

    if (strcmp(cmd, "connect") == 0) return cmd_connect();
    if (strcmp(cmd, "status") == 0) return cmd_status(n, args);
    if (strcmp(cmd, "list-guests") == 0) return cmd_list_guests();
    if (strcmp(cmd, "guest-status") == 0) return cmd_guest_status(n, args);
    if (strcmp(cmd, "list-devices") == 0) return cmd_list_devices(n, args);
    if (strcmp(cmd, "device-status") == 0 && n >= 2) {
        return cmd_simple(MSG_CC_DEVICE_STATUS,
                          parse_u32(args[0], "dev_type"),
                          parse_u32(args[1], "dev_handle"), 0);
    }
    if (strcmp(cmd, "polecats") == 0 || strcmp(cmd, "list-polecats") == 0) {
        return cmd_simple(MSG_CC_LIST_POLECATS, 0, 0, 0);
    }
    if (strcmp(cmd, "log-stream") == 0 && n >= 2) {
        return cmd_simple(MSG_CC_LOG_STREAM,
                          parse_u32(args[0], "slot"),
                          parse_u32(args[1], "pd_id"), 0);
    }
    if (strcmp(cmd, "fb-attach") == 0 && n >= 2) {
        return cmd_simple(MSG_CC_ATTACH_FRAMEBUFFER,
                          parse_u32(args[0], "guest_handle"),
                          parse_u32(args[1], "fb_handle"), 0);
    }
    if (strcmp(cmd, "send-input") == 0) return cmd_send_input(n, args);
    if (strcmp(cmd, "suspend") == 0 && n >= 1) {
        return cmd_simple(MSG_CC_SUSPEND_GUEST,
                          parse_u32(args[0], "guest_handle"), 0, 0);
    }
    if (strcmp(cmd, "resume") == 0 && n >= 1) {
        return cmd_simple(MSG_CC_RESUME_GUEST,
                          parse_u32(args[0], "guest_handle"), 0, 0);
    }
    if (strcmp(cmd, "destroy") == 0 && n >= 1) {
        return cmd_simple(MSG_CC_DESTROY_GUEST,
                          parse_u32(args[0], "guest_handle"),
                          n > 1 ? parse_u32(args[1], "reason") : GUEST_DESTROY_NORMAL,
                          0);
    }
    if (strcmp(cmd, "snapshot") == 0 && n >= 1) {
        return cmd_simple(MSG_CC_SNAPSHOT, parse_u32(args[0], "guest_handle"),
                          0, 0);
    }
    if (strcmp(cmd, "restore") == 0 && n >= 3) {
        return cmd_simple(MSG_CC_RESTORE,
                          parse_u32(args[0], "guest_handle"),
                          parse_u32(args[1], "snap_lo"),
                          parse_u32(args[2], "snap_hi"));
    }
    if (strcmp(cmd, "trace-start") == 0) {
        return cmd_simple(MSG_CC_TRACE_START,
                          n > 0 ? parse_u32(args[0], "flags") : CC_TRACE_FLAG_WRAP,
                          0, 0);
    }
    if (strcmp(cmd, "trace-stop") == 0) {
        return cmd_simple(MSG_CC_TRACE_STOP, 0, 0, 0);
    }
    if (strcmp(cmd, "trace-query") == 0) {
        return cmd_simple(MSG_CC_TRACE_QUERY, 0, 0, 0);
    }
    if (strcmp(cmd, "trace-dump") == 0) return cmd_trace_dump(n, args);
    if (strcmp(cmd, "agent-run") == 0) return cmd_agent_run(n, args, false);
    if (strcmp(cmd, "agent-run-file") == 0) return cmd_agent_run(n, args, true);
    if (strcmp(cmd, "mesh") == 0) return cmd_mesh(n, args);
    if (strcmp(cmd, "raw") == 0 && n >= 1) {
        return cmd_simple(parse_u32(args[0], "opcode"),
                          n > 1 ? parse_u32(args[1], "mr1") : 0,
                          n > 2 ? parse_u32(args[2], "mr2") : 0,
                          n > 3 ? parse_u32(args[3], "mr3") : 0);
    }

    fprintf(stderr, "agentctl: unknown or incomplete command: %s\n", cmd);
    usage(stderr);
    return 2;
}

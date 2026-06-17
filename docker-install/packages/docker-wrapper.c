/*
 * =========================================================================
 *  OpenClaw Sandbox Docker Secure Proxy
 * =========================================================================
 *  所有路径基于 INSTALL_PREFIX（编译时传入 -DINSTALL_PREFIX=/path）
 *  不修改 /usr/bin/docker，不影响系统已有 Docker
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>

#ifndef INSTALL_PREFIX
#define INSTALL_PREFIX "/opt/.sandbox-runtime"
#endif

#define REAL_DOCKER   INSTALL_PREFIX "/bin/.docker.secure"
#define LOG_FILE      INSTALL_PREFIX "/log/docker-audit.log"
#define DOCKER_SOCK   "unix://" INSTALL_PREFIX "/run/docker.sock"

#define MAX_LOG_LINE       4096
#define MAX_USERNAME       64
#define MAX_PIDS_COUNT     256
#define MAX_CACHE_LINE     8192
#define HTTP_BUF_SIZE      16384

#define SHM_CACHE_PATH "/dev/shm/sandbox_pids.cache"
#define SHM_TEMP_PATH  "/dev/shm/sandbox_pids.tmp"

#define SERVICE_HOST "127.0.0.1"
#define SERVICE_PORT 18901

typedef struct {
    pid_t pid;
} TrustedProcess;

typedef struct {
    const char *option;
    int need_value;
} DangerousOption;

static const DangerousOption dangerous_options[] = {
    {"--privileged", 0},
    {"--cap-add", 1},
    {"--security-opt", 1},
    {"--userns", 1},
    {"--pid", 1},
    {"--ipc", 1},
    {"--uts", 1},
    {NULL, 0}
};

static const char *danger_paths[] = {
    "/",
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/var/run/docker.sock",
    "/var/lib/docker",
    NULL
};

static void sanitize_string(char *dst, size_t dst_size, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        unsigned char c = src[i];
        if (c == '\n') {
            if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 'n'; }
        } else if (c == '\r') {
            if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 'r'; }
        } else if (c == '\t') {
            if (j + 2 < dst_size) { dst[j++] = '\\'; dst[j++] = 't'; }
        } else if (isprint(c)) {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

static void get_user_info(char *user_buf, char *sudo_buf)
{
    struct passwd *pw = getpwuid(getuid());
    snprintf(user_buf, MAX_USERNAME, "%s", pw ? pw->pw_name : "unknown");
    const char *s_user = getenv("SUDO_USER");
    snprintf(sudo_buf, MAX_USERNAME, "%s", s_user ? s_user : "none");
}

static void audit_log(int denied, const char *reason, int argc, char *argv[])
{
    char cmd[MAX_LOG_LINE] = {0};
    char safe_arg[1024];
    int offset = 0;

    for (int i = 0; i < argc; i++) {
        sanitize_string(safe_arg, sizeof(safe_arg), argv[i]);
        offset += snprintf(cmd + offset, sizeof(cmd) - offset, "%s ", safe_arg);
        if (offset >= (int)sizeof(cmd) - 1) break;
    }

    char user[MAX_USERNAME];
    char sudo_user[MAX_USERNAME];
    get_user_info(user, sudo_user);

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_info);

    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;

    flock(fd, LOCK_EX);
    dprintf(fd, "%s [%d] [%s] [%s(%s)] CMD=%s REASON=%s\n",
            ts, getpid(), denied ? "DENIED" : "ALLOW", user, sudo_user, cmd, reason ? reason : "");
    flock(fd, LOCK_UN);
    close(fd);
}

static int safe_open_cache(void)
{
    int fd = open(SHM_CACHE_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 077) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int read_cache(pid_t ppid)
{
    int fd = safe_open_cache();
    if (fd < 0) return 0;

    FILE *fp = fdopen(fd, "r");
    if (!fp) { close(fd); return 0; }

    char line[MAX_CACHE_LINE];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return 0; }
    fclose(fp);

    char *saveptr = NULL;
    char *token = strtok_r(line, ",", &saveptr);
    while (token) {
        pid_t pid = 0;
        if (sscanf(token, "%d", &pid) == 1) {
            if (pid == ppid) return 1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}

static void update_cache(TrustedProcess *list, int count)
{
    if (count <= 0) { unlink(SHM_CACHE_PATH); return; }
    int fd = open(SHM_TEMP_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return;

    FILE *fp = fdopen(fd, "w");
    if (!fp) { close(fd); return; }

    for (int i = 0; i < count; i++) {
        fprintf(fp, "%d%s", list[i].pid, (i == count - 1) ? "" : ",");
    }
    fflush(fp);
    fsync(fd);
    fclose(fp);
    rename(SHM_TEMP_PATH, SHM_CACHE_PATH);
}

static int fetch_remote(TrustedProcess *list, int *count_out)
{
    *count_out = 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVICE_PORT);
    inet_pton(AF_INET, SERVICE_HOST, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return 0; }

    const char *req = "GET /v1/openclaw/status HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(sock, req, strlen(req), 0);

    char buf[HTTP_BUF_SIZE];
    int total = 0;
    while (1) {
        int n = recv(sock, buf + total, sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += n;
        if (total >= (int)sizeof(buf) - 1) break;
    }
    buf[total] = '\0';
    close(sock);

    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return 0;
    body += 4;

    char *pids_start = strstr(body, "\"pids\":");
    if (!pids_start) return 0;
    pids_start += 6;

    char *array_start = strchr(pids_start, '[');
    char *array_end = strchr(pids_start, ']');
    if (!array_start || !array_end || array_start >= array_end) return 0;
    array_start++;

    int idx = 0;
    char *p = array_start;
    while (p < array_end && idx < MAX_PIDS_COUNT) {
        while (p < array_end && isspace((unsigned char)*p)) p++;
        if (p >= array_end) break;

        pid_t pid = 0;
        if (sscanf(p, "%d", &pid) == 1) {
            list[idx].pid = pid;
            idx++;
        }

        while (p < array_end && *p != ',' && *p != ']') p++;
        if (*p == ',') p++;
    }

    *count_out = idx;
    return idx > 0;
}

static int check_caller_auth(void)
{
    pid_t ppid = getppid();
    if (read_cache(ppid)) return 1;

    TrustedProcess list[MAX_PIDS_COUNT];
    int count = 0;
    if (!fetch_remote(list, &count)) return 0;

    update_cache(list, count);
    for (int i = 0; i < count; i++) {
        if (list[i].pid == ppid) return 1;
    }
    return 0;
}

static int is_danger_path(const char *path)
{
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) return 1;

    for (int i = 0; danger_paths[i]; i++) {
        size_t len = strlen(danger_paths[i]);
        if (strncmp(resolved, danger_paths[i], len) == 0) {
            if (resolved[len] == '\0' || resolved[len] == '/') {
                return 1;
            }
        }
    }
    return 0;
}

static int check_volume(const char *volume)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", volume);
    char *host = strtok(tmp, ":");
    if (!host) return 0;
    return !is_danger_path(host);
}

static int check_security(int argc, char *argv[], const char **msg)
{
    for (int i = 1; i < argc; i++) {
        for (int j = 0; dangerous_options[j].option != NULL; j++) {
            const char *opt = dangerous_options[j].option;
            int need_val = dangerous_options[j].need_value;
            size_t opt_len = strlen(opt);

            if (strcmp(argv[i], opt) == 0) {
                if (need_val && i + 1 < argc) {
                    if (strcmp(opt, "--cap-add") == 0 && (strcmp(argv[i+1], "SYS_ADMIN") == 0 || strcmp(argv[i+1], "ALL") == 0)) {
                        *msg = "拒绝危险 capability"; return 0;
                    }
                    if (strcmp(opt, "--security-opt") == 0 && strstr(argv[i+1], "unconfined")) {
                        *msg = "拒绝禁用安全配置"; return 0;
                    }
                    if (strcmp(opt, "--userns") == 0 || strcmp(opt, "--pid") == 0 || strcmp(opt, "--ipc") == 0 || strcmp(opt, "--uts") == 0) {
                        *msg = "拒绝危险的命名空间/隔离参数"; return 0;
                    }
                } else if (!need_val) {
                    if (strcmp(opt, "--privileged") == 0) { *msg = "拒绝 privileged"; return 0; }
                }
            }

            if (strncmp(argv[i], opt, opt_len) == 0 && argv[i][opt_len] == '=') {
                const char *val = argv[i] + opt_len + 1;
                if (strcmp(opt, "--cap-add") == 0 && (strcmp(val, "SYS_ADMIN") == 0 || strcmp(val, "ALL") == 0)) {
                    *msg = "拒绝危险 capability"; return 0;
                }
                if (strcmp(opt, "--security-opt") == 0 && strstr(val, "unconfined")) {
                    *msg = "拒绝禁用安全配置"; return 0;
                }
                if (strcmp(opt, "--userns") == 0 || strcmp(opt, "--pid") == 0 || strcmp(opt, "--ipc") == 0 || strcmp(opt, "--uts") == 0) {
                    *msg = "拒绝危险的命名空间/隔离参数"; return 0;
                }
            }
        }

        if (strcmp(argv[i], "--network=host") == 0 || strcmp(argv[i], "--net=host") == 0) {
            *msg = "拒绝 host network";
            return 0;
        }

        const char *volume = NULL;
        if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) { volume = argv[i + 1]; }
        else if (strncmp(argv[i], "-v", 2) == 0) { volume = argv[i] + 2; }
        else if (strcmp(argv[i], "--volume") == 0 && i + 1 < argc) { volume = argv[i + 1]; }
        else if (strncmp(argv[i], "--volume=", 9) == 0) { volume = argv[i] + 9; }

        if (volume && !check_volume(volume)) {
            *msg = "拒绝挂载敏感目录";
            return 0;
        }
    }
    return 1;
}

static void sanitize_environment(void)
{
    clearenv();
    setenv("PATH", INSTALL_PREFIX "/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);
    setenv("TERM", "xterm", 1);
    setenv("DOCKER_HOST", DOCKER_SOCK, 1);
}

int main(int argc, char *argv[])
{
    if (argc < 1) return 1;
    const char *deny_msg = NULL;

    if (!check_caller_auth()) {
        deny_msg = "未通过 OpenClaw Runtime 认证";
        audit_log(1, deny_msg, argc, argv);
        fprintf(stderr, "安全限制: %s\n", deny_msg);
        return 1;
    }

    if (!check_security(argc, argv, &deny_msg)) {
        audit_log(1, deny_msg, argc, argv);
        fprintf(stderr, "安全限制: %s\n", deny_msg);
        return 1;
    }

    audit_log(0, "", argc, argv);
    sanitize_environment();

    argv[0] = (char *)REAL_DOCKER;
    execv(REAL_DOCKER, argv);

    fprintf(stderr, "exec docker failed: %s\n", strerror(errno));
    return 1;
}
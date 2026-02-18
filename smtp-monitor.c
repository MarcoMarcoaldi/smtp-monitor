/*
 * smtp-monitor.c - SMTP Connection Monitor v1.0
 *
 * Monitors real-time connections to SMTP ports (25, 465, 587, 2525)
 * by reading /var/log/audit/audit.log in real-time via inotify.
 * Fully coexists with auditd.
 *
 * Build:
 *   gcc -O2 -o smtp-monitor smtp-monitor.c -lncurses -lpthread
 *
 * Usage:
 *   ./smtp-monitor          # interactive mode (ncurses TUI)
 *   ./smtp-monitor -l       # log to stdout
 *   ./smtp-monitor -f file  # log to file
 *
 * By Managed Server S.r.l. — https://managedserver.it
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ncurses.h>
#include <locale.h>

/* ============================================================================
 * Constants
 * ============================================================================ */
#define MAX_EVENTS      10000
#define LINE_BUF_SIZE   4096
#define AUDIT_LOG_PATH  "/var/log/audit/audit.log"
#define AUDIT_LOG_DIR   "/var/log/audit"

/* SMTP ports in hex (network byte order in saddr) */
#define SMTP_HEX_25     "0019"
#define SMTP_HEX_465    "01D1"
#define SMTP_HEX_465L   "01d1"
#define SMTP_HEX_587    "024B"
#define SMTP_HEX_587L   "024b"
#define SMTP_HEX_2525   "09DD"
#define SMTP_HEX_2525L  "09dd"

/* Color pairs */
#define CP_HEADER     1
#define CP_STATUS     2
#define CP_STATUS_LIVE 3
#define CP_STATUS_PAUSED 4
#define CP_COL_HEADER 5
#define CP_TIMESTAMP  6
#define CP_USER       7
#define CP_PID        8
#define CP_PROCESS    9
#define CP_PORT_25    10
#define CP_PORT_465   11
#define CP_PORT_587   12
#define CP_PORT_2525  13
#define CP_CWD        14
#define CP_FOOTER     15
#define CP_KEY        16
#define CP_RDNS       17
#define CP_POPUP_BG   18
#define CP_POPUP_TITLE 19
#define CP_POPUP_URL  20
#define CP_POPUP_DIM  21
#define CP_POPUP_SEP  22
#define CP_SEPARATOR  23

/* ============================================================================
 * Structures
 * ============================================================================ */
typedef struct {
    time_t      timestamp;
    uint16_t    port;
    uint32_t    pid;
    uint32_t    uid;
    char        user[64];
    char        exe[256];
    char        comm[64];
    char        dest_ip[INET6_ADDRSTRLEN + 8];
    char        cwd[256];
    char        rdns[256];
    int         rdns_resolved;  /* 0=pending, 1=done, -1=failed */
} smtp_event_t;

typedef struct {
    smtp_event_t events[MAX_EVENTS];
    int          count;
    int          head;
    pthread_mutex_t lock;
} event_buffer_t;

/* SYSCALL cache for SOCKADDR correlation via msg serial */
#define CACHE_SIZE 4096
typedef struct {
    uint32_t serial;
    uint32_t pid;
    uint32_t uid;
    uint32_t euid;
    char     exe[256];
    char     comm[64];
    char     cwd[256];
} cache_entry_t;

/* ============================================================================
 * Globals
 * ============================================================================ */
static volatile int g_running = 1;
static int g_mode = 0;          /* 0=interactive, 1=log, 2=file */
static FILE *g_logfile = NULL;
static event_buffer_t g_events;
static int g_paused = 0;
static int g_scroll_offset = 0;
static int g_show_rdns = 0;    /* RDNS column toggle */
static char g_audit_key[64] = "";
static int g_needs_redraw = 1; /* Flag to trigger UI refresh */

/* SYSCALL circular cache */
static cache_entry_t g_cache[CACHE_SIZE];
static int g_cache_pos = 0;
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* DNS cache to avoid repeated lookups */
#define DNS_CACHE_SIZE 512
typedef struct {
    char ip[INET6_ADDRSTRLEN + 8];
    char rdns[256];
    int  resolved;  /* 0=pending, 1=ok, -1=failed */
} dns_cache_entry_t;

static dns_cache_entry_t g_dns_cache[DNS_CACHE_SIZE];
static int g_dns_cache_count = 0;
static pthread_mutex_t g_dns_lock = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
static int event_get(int index, smtp_event_t *ev);
static int event_count(void);

/* ============================================================================
 * Helper functions
 * ============================================================================ */
static void resolve_user(uint32_t uid, char *out, size_t sz)
{
    struct passwd *pw = getpwuid(uid);
    if (pw)
        snprintf(out, sz, "%s", pw->pw_name);
    else
        snprintf(out, sz, "uid:%u", uid);
}

/* Read euid from /proc/PID/status as fallback */
static uint32_t read_euid_from_proc(uint32_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return (uint32_t)-1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            uint32_t ruid, euid;
            if (sscanf(line, "Uid:\t%u\t%u", &ruid, &euid) == 2) {
                fclose(f);
                return euid;
            }
        }
    }
    fclose(f);
    return (uint32_t)-1;
}

/* Read CWD from /proc */
static void read_cwd_from_proc(uint32_t pid, char *out, size_t sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/cwd", pid);
    ssize_t len = readlink(path, out, sz - 1);
    if (len > 0) out[len] = '\0';
    else out[0] = '\0';
}

/* ============================================================================
 * Parser: extract fields from audit text records
 *
 * Typical format:
 * type=SYSCALL ... pid=1087389 ... uid=1039 ... euid=1039 ... comm="php-fpm" exe="/opt/..."
 * type=SOCKADDR ... saddr=0200024B8EFB7F6D0000000000000000
 * type=CWD ... cwd="/home/site/htdocs"
 * ============================================================================ */

/* Find "key=" as a whole word (not part of fsuid, suid, etc) */
static uint32_t parse_uint_field(const char *line, const char *field)
{
    size_t flen = strlen(field);
    const char *p = line;

    while ((p = strstr(p, field)) != NULL) {
        /* Previous char must be space, or start of string */
        if (p != line) {
            char prev = *(p - 1);
            if (prev != ' ' && prev != ')' && prev != ':' && prev != '\t') {
                p += flen;
                continue;
            }
        }
        if (p[flen] == '=') {
            return (uint32_t)strtoul(p + flen + 1, NULL, 10);
        }
        p += flen;
    }
    return 0;
}

/* Extract quoted string: field="value" */
static int parse_str_field(const char *line, const char *field, char *out, size_t out_sz)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "%s=\"", field);
    const char *p = strstr(line, pattern);
    if (!p) return 0;
    p += strlen(pattern);
    const char *end = strchr(p, '"');
    if (!end) return 0;
    size_t len = (size_t)(end - p);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

/* Extract the serial from msg=audit(TIMESTAMP:SERIAL): */
static uint32_t parse_serial(const char *line)
{
    const char *p = strstr(line, "msg=audit(");
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    return (uint32_t)strtoul(p + 1, NULL, 10);
}

/* Detect record type from line */
static int detect_type(const char *line)
{
    if (strncmp(line, "type=SYSCALL ", 13) == 0) return 1;
    if (strncmp(line, "type=SOCKADDR ", 14) == 0) return 2;
    if (strncmp(line, "type=CWD ", 9) == 0) return 3;
    return 0;
}

/* Decode saddr hex string.
 * Returns port in *port_out and IP in ip_out.
 * Returns 1 if SMTP, 0 otherwise.
 */
static int decode_saddr(const char *line, char *ip_out, size_t ip_sz, uint16_t *port_out)
{
    const char *p = strstr(line, "saddr=");
    if (!p) return 0;
    p += 6;

    /* Read first 8 hex chars: family(4) + port(4) */
    if (strlen(p) < 8) return 0;

    /* Validate hex chars */
    for (int i = 0; i < 8; i++) {
        char c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
            return 0;
    }

    char family_hex[5] = { p[0], p[1], p[2], p[3], 0 };
    char port_hex[5]   = { p[4], p[5], p[6], p[7], 0 };

    /* Filter SMTP ports only */
    uint16_t port = 0;
    if (strcmp(port_hex, SMTP_HEX_25) == 0) port = 25;
    else if (strcmp(port_hex, SMTP_HEX_465) == 0 || strcmp(port_hex, SMTP_HEX_465L) == 0) port = 465;
    else if (strcmp(port_hex, SMTP_HEX_587) == 0 || strcmp(port_hex, SMTP_HEX_587L) == 0) port = 587;
    else if (strcmp(port_hex, SMTP_HEX_2525) == 0 || strcmp(port_hex, SMTP_HEX_2525L) == 0) port = 2525;
    else return 0;

    *port_out = port;

    if (strcmp(family_hex, "0200") == 0) {
        /* IPv4 */
        if (strlen(p) < 16) return 0;
        unsigned int o[4];
        char h[3];
        for (int i = 0; i < 4; i++) {
            h[0] = p[8 + i*2];
            h[1] = p[9 + i*2];
            h[2] = 0;
            o[i] = (unsigned int)strtoul(h, NULL, 16);
        }
        snprintf(ip_out, ip_sz, "%u.%u.%u.%u", o[0], o[1], o[2], o[3]);
        /* Skip localhost */
        if (strcmp(ip_out, "127.0.0.1") == 0) return 0;
        return 1;
    }
    else if (strcmp(family_hex, "0A00") == 0 || strcmp(family_hex, "0a00") == 0) {
        /* IPv6 */
        if (strlen(p) < 48) return 0;
        unsigned char addr6[16];
        for (int i = 0; i < 16; i++) {
            char h[3] = { p[16 + i*2], p[17 + i*2], 0 };
            addr6[i] = (unsigned char)strtoul(h, NULL, 16);
        }
        inet_ntop(AF_INET6, addr6, ip_out, ip_sz);
        if (strcmp(ip_out, "::1") == 0) return 0;
        return 1;
    }

    return 0;
}

/* ============================================================================
 * SYSCALL correlation cache
 * ============================================================================ */
static void cache_put(uint32_t serial, uint32_t pid, uint32_t uid, uint32_t euid,
                      const char *exe, const char *comm)
{
    pthread_mutex_lock(&g_cache_lock);
    int idx = g_cache_pos % CACHE_SIZE;
    g_cache[idx].serial = serial;
    g_cache[idx].pid = pid;
    g_cache[idx].uid = uid;
    g_cache[idx].euid = euid;
    strncpy(g_cache[idx].exe, exe, sizeof(g_cache[idx].exe) - 1);
    g_cache[idx].exe[sizeof(g_cache[idx].exe) - 1] = '\0';
    strncpy(g_cache[idx].comm, comm, sizeof(g_cache[idx].comm) - 1);
    g_cache[idx].comm[sizeof(g_cache[idx].comm) - 1] = '\0';
    g_cache[idx].cwd[0] = '\0';
    g_cache_pos++;
    pthread_mutex_unlock(&g_cache_lock);
}

static void cache_update_cwd(uint32_t serial, const char *cwd)
{
    pthread_mutex_lock(&g_cache_lock);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (g_cache[i].serial == serial) {
            strncpy(g_cache[i].cwd, cwd, sizeof(g_cache[i].cwd) - 1);
            g_cache[i].cwd[sizeof(g_cache[i].cwd) - 1] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
}

static int cache_get(uint32_t serial, uint32_t *pid, uint32_t *uid, uint32_t *euid,
                     char *exe, size_t exe_sz, char *comm, size_t comm_sz,
                     char *cwd, size_t cwd_sz)
{
    pthread_mutex_lock(&g_cache_lock);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (g_cache[i].serial == serial) {
            *pid = g_cache[i].pid;
            *uid = g_cache[i].uid;
            *euid = g_cache[i].euid;
            strncpy(exe, g_cache[i].exe, exe_sz - 1); exe[exe_sz-1] = '\0';
            strncpy(comm, g_cache[i].comm, comm_sz - 1); comm[comm_sz-1] = '\0';
            strncpy(cwd, g_cache[i].cwd, cwd_sz - 1); cwd[cwd_sz-1] = '\0';
            pthread_mutex_unlock(&g_cache_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_cache_lock);
    return 0;
}

/* ============================================================================
 * DNS Reverse Cache and Resolver
 * ============================================================================ */

/* Lookup DNS cache. Returns 1 if found, 0 if not present */
static int dns_cache_lookup(const char *ip, char *rdns, size_t rdns_sz, int *resolved)
{
    pthread_mutex_lock(&g_dns_lock);
    for (int i = 0; i < g_dns_cache_count; i++) {
        if (strcmp(g_dns_cache[i].ip, ip) == 0) {
            strncpy(rdns, g_dns_cache[i].rdns, rdns_sz - 1);
            rdns[rdns_sz - 1] = '\0';
            *resolved = g_dns_cache[i].resolved;
            pthread_mutex_unlock(&g_dns_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_dns_lock);
    return 0;
}

/* Add or update DNS cache entry */
static void dns_cache_set(const char *ip, const char *rdns, int resolved)
{
    pthread_mutex_lock(&g_dns_lock);
    /* Check if already exists */
    for (int i = 0; i < g_dns_cache_count; i++) {
        if (strcmp(g_dns_cache[i].ip, ip) == 0) {
            strncpy(g_dns_cache[i].rdns, rdns, sizeof(g_dns_cache[i].rdns) - 1);
            g_dns_cache[i].rdns[sizeof(g_dns_cache[i].rdns) - 1] = '\0';
            g_dns_cache[i].resolved = resolved;
            pthread_mutex_unlock(&g_dns_lock);
            return;
        }
    }
    /* Add new entry */
    if (g_dns_cache_count < DNS_CACHE_SIZE) {
        int idx = g_dns_cache_count++;
        strncpy(g_dns_cache[idx].ip, ip, sizeof(g_dns_cache[idx].ip) - 1);
        g_dns_cache[idx].ip[sizeof(g_dns_cache[idx].ip) - 1] = '\0';
        strncpy(g_dns_cache[idx].rdns, rdns, sizeof(g_dns_cache[idx].rdns) - 1);
        g_dns_cache[idx].rdns[sizeof(g_dns_cache[idx].rdns) - 1] = '\0';
        g_dns_cache[idx].resolved = resolved;
    }
    pthread_mutex_unlock(&g_dns_lock);
}

/* Resolve reverse DNS for an IP */
static void resolve_rdns(const char *ip, char *rdns, size_t rdns_sz)
{
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));

    struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        ss_len = sizeof(*v4);
    } else if (inet_pton(AF_INET6, ip, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        ss_len = sizeof(*v6);
    } else {
        snprintf(rdns, rdns_sz, "-");
        return;
    }

    char host[256] = "";
    int ret = getnameinfo((struct sockaddr *)&ss, ss_len,
                          host, sizeof(host), NULL, 0, NI_NAMEREQD);
    if (ret == 0 && host[0]) {
        snprintf(rdns, rdns_sz, "%s", host);
    } else {
        snprintf(rdns, rdns_sz, "-");
    }
}

/* Thread that resolves RDNS in background for all events */
static void *rdns_resolver_thread(void *arg)
{
    (void)arg;
    while (g_running) {
        if (!g_show_rdns) {
            usleep(500000);
            continue;
        }

        int total = event_count();
        for (int i = 0; i < total && g_running && g_show_rdns; i++) {
            smtp_event_t ev;
            if (!event_get(i, &ev)) continue;
            if (ev.dest_ip[0] == '\0') continue;

            char rdns[256] = "";
            int resolved = 0;
            if (dns_cache_lookup(ev.dest_ip, rdns, sizeof(rdns), &resolved)) {
                if (ev.rdns_resolved == 0 && resolved != 0) {
                    pthread_mutex_lock(&g_events.lock);
                    int real = (g_events.head + i) % MAX_EVENTS;
                    if (i < g_events.count) {
                        strncpy(g_events.events[real].rdns, rdns, sizeof(g_events.events[real].rdns) - 1);
                        g_events.events[real].rdns_resolved = resolved;
                    }
                    pthread_mutex_unlock(&g_events.lock);
                    g_needs_redraw = 1;
                }
                continue;
            }

            dns_cache_set(ev.dest_ip, "resolving...", 0);

            resolve_rdns(ev.dest_ip, rdns, sizeof(rdns));
            int status = (strcmp(rdns, "-") == 0) ? -1 : 1;
            dns_cache_set(ev.dest_ip, rdns, status);

            /* Update all events with this IP */
            pthread_mutex_lock(&g_events.lock);
            for (int j = 0; j < g_events.count; j++) {
                int real = (g_events.head + j) % MAX_EVENTS;
                if (strcmp(g_events.events[real].dest_ip, ev.dest_ip) == 0) {
                    strncpy(g_events.events[real].rdns, rdns, sizeof(g_events.events[real].rdns) - 1);
                    g_events.events[real].rdns_resolved = status;
                }
            }
            pthread_mutex_unlock(&g_events.lock);
            g_needs_redraw = 1;
        }
        usleep(500000);
    }
    return NULL;
}

/* ============================================================================
 * Event buffer
 * ============================================================================ */
static void event_add(smtp_event_t *ev)
{
    pthread_mutex_lock(&g_events.lock);
    int idx;
    if (g_events.count < MAX_EVENTS) {
        idx = g_events.count++;
    } else {
        idx = g_events.head;
        g_events.head = (g_events.head + 1) % MAX_EVENTS;
    }
    memcpy(&g_events.events[idx % MAX_EVENTS], ev, sizeof(*ev));
    pthread_mutex_unlock(&g_events.lock);
    g_needs_redraw = 1;
}

static int event_get(int index, smtp_event_t *ev)
{
    pthread_mutex_lock(&g_events.lock);
    if (index < 0 || index >= g_events.count) {
        pthread_mutex_unlock(&g_events.lock);
        return 0;
    }
    int real = (g_events.head + index) % MAX_EVENTS;
    memcpy(ev, &g_events.events[real], sizeof(*ev));
    pthread_mutex_unlock(&g_events.lock);
    return 1;
}

static int event_count(void)
{
    pthread_mutex_lock(&g_events.lock);
    int c = g_events.count;
    pthread_mutex_unlock(&g_events.lock);
    return c;
}

static void event_clear(void)
{
    pthread_mutex_lock(&g_events.lock);
    g_events.count = 0;
    g_events.head = 0;
    pthread_mutex_unlock(&g_events.lock);
    g_needs_redraw = 1;
}

/* ============================================================================
 * Process a single audit log line
 * ============================================================================ */
static void process_line(const char *line)
{
    int type = detect_type(line);
    if (type == 0) return;

    uint32_t serial = parse_serial(line);
    if (serial == 0) return;

    if (type == 1) {
        /* SYSCALL: save to cache */
        uint32_t pid  = parse_uint_field(line, "pid");
        uint32_t uid  = parse_uint_field(line, "uid");
        uint32_t euid = parse_uint_field(line, "euid");
        char exe[256] = "", comm[64] = "";
        parse_str_field(line, "exe", exe, sizeof(exe));
        parse_str_field(line, "comm", comm, sizeof(comm));
        cache_put(serial, pid, uid, euid, exe, comm);
    }
    else if (type == 3) {
        /* CWD: update cache */
        char cwd[256] = "";
        parse_str_field(line, "cwd", cwd, sizeof(cwd));
        if (cwd[0])
            cache_update_cwd(serial, cwd);
    }
    else if (type == 2) {
        /* SOCKADDR: decode and filter SMTP ports */
        char ip[INET6_ADDRSTRLEN + 8];
        uint16_t port = 0;
        memset(ip, 0, sizeof(ip));

        if (!decode_saddr(line, ip, sizeof(ip), &port))
            return;

        /* Create event */
        smtp_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.timestamp = time(NULL);
        ev.port = port;
        strncpy(ev.dest_ip, ip, sizeof(ev.dest_ip) - 1);

        /* Correlate with SYSCALL */
        uint32_t euid = 0;
        if (cache_get(serial, &ev.pid, &ev.uid, &euid,
                      ev.exe, sizeof(ev.exe),
                      ev.comm, sizeof(ev.comm),
                      ev.cwd, sizeof(ev.cwd))) {

            /* Prefer euid (effective UID) for php-fpm workers */
            uint32_t display_uid = euid;

            /* Fallback: read from /proc if euid=0 but not actually root */
            if (display_uid == 0 && ev.pid > 0) {
                uint32_t proc_euid = read_euid_from_proc(ev.pid);
                if (proc_euid != (uint32_t)-1)
                    display_uid = proc_euid;
            }

            resolve_user(display_uid, ev.user, sizeof(ev.user));

            /* CWD fallback from /proc */
            if (ev.cwd[0] == '\0' && ev.pid > 0)
                read_cwd_from_proc(ev.pid, ev.cwd, sizeof(ev.cwd));
        } else {
            strcpy(ev.user, "?");
            strcpy(ev.exe, "unknown");
        }

        event_add(&ev);

        /* Output for log/file mode */
        if (g_mode == 1 || g_mode == 2) {
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&ev.timestamp));
            const char *proc = ev.exe[0] ? strrchr(ev.exe, '/') : NULL;
            proc = proc ? proc + 1 : (ev.comm[0] ? ev.comm : ev.exe);

            FILE *out = (g_mode == 1) ? stdout : g_logfile;
            fprintf(out, "[%s] USER=%-33s PID=%-8u PROC=%-25s PORT=%-5u DST=%-40s CWD=%s\n",
                    ts, ev.user, ev.pid, proc, ev.port, ev.dest_ip, ev.cwd);
            fflush(out);
        }
    }
}

/* ============================================================================
 * Thread: reads audit.log with inotify (like tail -F)
 * ============================================================================ */
static void *log_reader_thread(void *arg)
{
    (void)arg;

    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) {
        perror("inotify_init1");
        return NULL;
    }

    int dir_wd = inotify_add_watch(inotify_fd, AUDIT_LOG_DIR,
                                    IN_CREATE | IN_MOVED_TO);
    if (dir_wd < 0) {
        perror("inotify_add_watch dir");
        close(inotify_fd);
        return NULL;
    }

    char line_buf[LINE_BUF_SIZE];
    int line_pos = 0;

reopen:;
    FILE *fp = fopen(AUDIT_LOG_PATH, "r");
    if (!fp) {
        perror("fopen audit.log");
        close(inotify_fd);
        return NULL;
    }

    /* Seek to end — we only want new events */
    fseek(fp, 0, SEEK_END);
    long last_pos = ftell(fp);
    struct stat last_stat;
    fstat(fileno(fp), &last_stat);
    ino_t last_ino = last_stat.st_ino;

    int file_wd = inotify_add_watch(inotify_fd, AUDIT_LOG_PATH, IN_MODIFY);

    while (g_running) {
        struct pollfd pfd = { .fd = inotify_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 500);

        if (ret > 0) {
            char ibuf[4096];
            ssize_t r = read(inotify_fd, ibuf, sizeof(ibuf));
            (void)r;
        }

        /* Check if file was rotated (new inode) */
        struct stat cur_stat;
        if (stat(AUDIT_LOG_PATH, &cur_stat) == 0 && cur_stat.st_ino != last_ino) {
            if (file_wd >= 0) inotify_rm_watch(inotify_fd, file_wd);
            fclose(fp);
            line_pos = 0;
            goto reopen;
        }

        /* Read new lines */
        fseek(fp, last_pos, SEEK_SET);
        while (fgets(line_buf + line_pos, LINE_BUF_SIZE - line_pos, fp)) {
            size_t total_len = strlen(line_buf);

            if (total_len > 0 && line_buf[total_len - 1] == '\n') {
                line_buf[total_len - 1] = '\0';
                process_line(line_buf);
                line_pos = 0;
                line_buf[0] = '\0';
            } else {
                line_pos = (int)total_len;
            }
        }
        last_pos = ftell(fp);
        clearerr(fp);
    }

    fclose(fp);
    if (file_wd >= 0) inotify_rm_watch(inotify_fd, file_wd);
    inotify_rm_watch(inotify_fd, dir_wd);
    close(inotify_fd);
    return NULL;
}

/* ============================================================================
 * Audit rule management via system("auditctl ...")
 * ============================================================================ */
static void audit_add_rules(void)
{
    snprintf(g_audit_key, sizeof(g_audit_key), "smtp_mon_%d", getpid());

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "auditctl -a always,exit -F arch=b64 -S connect -k %s 2>/dev/null", g_audit_key);
    (void)system(cmd);

    snprintf(cmd, sizeof(cmd),
             "auditctl -a always,exit -F arch=b32 -S connect -k %s 2>/dev/null", g_audit_key);
    (void)system(cmd);
}

static void audit_del_rules(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "auditctl -d always,exit -F arch=b64 -S connect -k %s 2>/dev/null", g_audit_key);
    (void)system(cmd);

    snprintf(cmd, sizeof(cmd),
             "auditctl -d always,exit -F arch=b32 -S connect -k %s 2>/dev/null", g_audit_key);
    (void)system(cmd);
}

/* ============================================================================
 * ncurses UI
 * ============================================================================ */
static void init_colors(void)
{
    start_color();
    use_default_colors();

    init_pair(CP_HEADER,       COLOR_WHITE,  COLOR_BLUE);
    init_pair(CP_STATUS,       COLOR_WHITE,  COLOR_BLACK);
    init_pair(CP_STATUS_LIVE,  COLOR_WHITE,  COLOR_GREEN);
    init_pair(CP_STATUS_PAUSED,COLOR_WHITE,  COLOR_RED);
    init_pair(CP_COL_HEADER,   COLOR_YELLOW, -1);
    init_pair(CP_TIMESTAMP,    COLOR_WHITE,  -1);
    init_pair(CP_USER,         COLOR_CYAN,   -1);
    init_pair(CP_PID,          COLOR_WHITE,  -1);
    init_pair(CP_PROCESS,      COLOR_WHITE,  -1);
    init_pair(CP_PORT_25,      COLOR_RED,    -1);
    init_pair(CP_PORT_465,     COLOR_GREEN,  -1);
    init_pair(CP_PORT_587,     COLOR_CYAN,   -1);
    init_pair(CP_PORT_2525,    COLOR_MAGENTA,-1);
    init_pair(CP_CWD,          COLOR_WHITE,  -1);
    init_pair(CP_FOOTER,       COLOR_WHITE,  COLOR_BLACK);
    init_pair(CP_KEY,          COLOR_WHITE,  COLOR_BLACK);
    init_pair(CP_RDNS,         COLOR_GREEN,  -1);
    init_pair(CP_POPUP_BG,     COLOR_WHITE,  COLOR_BLUE);
    init_pair(CP_POPUP_TITLE,  COLOR_YELLOW, COLOR_BLUE);
    init_pair(CP_POPUP_URL,    COLOR_GREEN,  COLOR_BLUE);
    init_pair(CP_POPUP_DIM,    COLOR_CYAN,   COLOR_BLUE);
    init_pair(CP_POPUP_SEP,    COLOR_CYAN,   COLOR_BLUE);
    init_pair(CP_SEPARATOR,    COLOR_WHITE,  -1);
}

static int port_color_pair(uint16_t port)
{
    switch (port) {
    case 25:   return CP_PORT_25;
    case 465:  return CP_PORT_465;
    case 587:  return CP_PORT_587;
    case 2525: return CP_PORT_2525;
    default:   return CP_PROCESS;
    }
}

static const char *port_label(uint16_t port)
{
    switch (port) {
    case 25:   return "SMTP";
    case 465:  return "SMTPS";
    case 587:  return "SUBMISSION";
    case 2525: return "SMTP-ALT";
    default:   return "???";
    }
}

static void draw_header(int cols)
{
    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    int total = event_count();

    /* Row 0: title bar */
    attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    mvprintw(0, 1, " SMTP CONNECTION MONITOR v1.0");
    mvprintw(0, cols - 21, "%s ", ts);
    attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

    /* Row 1: status bar */
    attron(COLOR_PAIR(CP_FOOTER));
    mvhline(1, 0, ' ', cols);
    mvaddch(1, 1, ' ');

    if (g_paused) {
        attron(COLOR_PAIR(CP_STATUS_PAUSED) | A_BOLD);
        printw(" PAUSED ");
        attroff(COLOR_PAIR(CP_STATUS_PAUSED) | A_BOLD);
    } else {
        attron(COLOR_PAIR(CP_STATUS_LIVE) | A_BOLD);
        printw("  LIVE  ");
        attroff(COLOR_PAIR(CP_STATUS_LIVE) | A_BOLD);
    }

    attron(COLOR_PAIR(CP_FOOTER));
    printw(" Events: ");
    attron(A_BOLD);
    printw("%d", total);
    attroff(A_BOLD);
    printw(" | Ports: ");
    attron(A_BOLD);
    printw("25 465 587 2525");
    attroff(A_BOLD);
    printw(" | RDNS: ");
    attron(A_BOLD);
    printw("%s", g_show_rdns ? "ON" : "OFF");
    attroff(A_BOLD);
    attroff(COLOR_PAIR(CP_FOOTER));

    /* Row 3: column headers */
    attron(COLOR_PAIR(CP_COL_HEADER) | A_BOLD);
    mvhline(3, 0, ' ', cols);
    mvprintw(3, 0, "%-20s %-33s %-8s %-22s %-6s %-12s %-28s",
             "TIMESTAMP", "USER", "PID", "PROCESS", "PORT", "PROTO", "DESTINATION");
    if (g_show_rdns)
        printw(" %-30s %s", "RDNS", "CWD");
    else
        printw(" %s", "CWD");
    attroff(COLOR_PAIR(CP_COL_HEADER) | A_BOLD);

    /* Row 4: separator */
    attron(COLOR_PAIR(CP_SEPARATOR) | A_DIM);
    mvhline(4, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(CP_SEPARATOR) | A_DIM);
}

static void draw_events(int rows, int cols)
{
    int data_rows = rows - 7;  /* header(5) + footer separator(1) + footer(1) */
    if (data_rows < 1) data_rows = 1;

    int total = event_count();

    int start_idx;
    if (!g_paused) {
        start_idx = total - data_rows;
        if (start_idx < 0) start_idx = 0;
        g_scroll_offset = 0;
    } else {
        start_idx = total - data_rows - g_scroll_offset;
        if (start_idx < 0) start_idx = 0;
    }

    for (int i = 0; i < data_rows; i++) {
        int row = 5 + i;
        move(row, 0);
        clrtoeol();

        int idx = start_idx + i;
        smtp_event_t ev;
        if (!event_get(idx, &ev)) continue;

        char ets[32];
        strftime(ets, sizeof(ets), "%Y-%m-%d %H:%M:%S", localtime(&ev.timestamp));
        const char *proc = ev.exe[0] ? strrchr(ev.exe, '/') : NULL;
        proc = proc ? proc + 1 : (ev.comm[0] ? ev.comm : "???");
        int pc = port_color_pair(ev.port);
        const char *pl = port_label(ev.port);

        /* Timestamp */
        attron(A_DIM);
        mvprintw(row, 0, "%-20s", ets);
        attroff(A_DIM);

        /* User */
        attron(COLOR_PAIR(CP_USER) | A_BOLD);
        mvprintw(row, 21, "%-33s", ev.user);
        attroff(COLOR_PAIR(CP_USER) | A_BOLD);

        /* PID */
        attron(A_DIM);
        mvprintw(row, 55, "%-8u", ev.pid);
        attroff(A_DIM);

        /* Process */
        attron(COLOR_PAIR(CP_PROCESS) | A_BOLD);
        mvprintw(row, 64, "%-22s", proc);
        attroff(COLOR_PAIR(CP_PROCESS) | A_BOLD);

        /* Port */
        attron(COLOR_PAIR(pc) | A_BOLD);
        mvprintw(row, 87, "%-6u", ev.port);
        attroff(COLOR_PAIR(pc) | A_BOLD);

        /* Proto */
        attron(COLOR_PAIR(pc) | A_BOLD);
        mvprintw(row, 94, "%-12s", pl);
        attroff(COLOR_PAIR(pc) | A_BOLD);

        /* Destination */
        attron(COLOR_PAIR(CP_PROCESS) | A_BOLD);
        mvprintw(row, 107, "%-28s", ev.dest_ip);
        attroff(COLOR_PAIR(CP_PROCESS) | A_BOLD);

        int col_next = 136;

        /* RDNS (optional) */
        if (g_show_rdns) {
            const char *rdns_str = ev.rdns[0] ? ev.rdns :
                                   (ev.rdns_resolved == 0 ? "resolving..." : "-");
            attron(COLOR_PAIR(CP_RDNS));
            mvprintw(row, col_next, "%-30s", rdns_str);
            attroff(COLOR_PAIR(CP_RDNS));
            col_next += 31;
        }

        /* CWD */
        attron(A_DIM);
        mvprintw(row, col_next, "%s", ev.cwd);
        attroff(A_DIM);
    }
}

static void draw_footer(int rows, int cols)
{
    /* Separator */
    attron(A_DIM);
    mvhline(rows - 2, 0, ACS_HLINE, cols);
    attroff(A_DIM);

    /* Footer */
    attron(COLOR_PAIR(CP_FOOTER));
    mvhline(rows - 1, 0, ' ', cols);
    move(rows - 1, 1);

    attron(A_BOLD);  printw("[P]"); attroff(A_BOLD); printw("ause  ");
    attron(A_BOLD);  printw("[C]"); attroff(A_BOLD); printw("lear  ");
    attron(A_BOLD);  printw("[R]"); attroff(A_BOLD); printw("DNS  ");
    attron(A_BOLD);  printw("[I]"); attroff(A_BOLD); printw("nfo  ");
    attron(A_BOLD);  printw("["); printw("Up/Dn"); printw("]"); attroff(A_BOLD); printw("Scroll  ");
    attron(A_BOLD);  printw("[PgUp/Dn]"); attroff(A_BOLD); printw("Page  ");
    attron(A_BOLD);  printw("[Q]"); attroff(A_BOLD); printw("uit");

    attroff(COLOR_PAIR(CP_FOOTER));
}

static void draw_ui(void)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    erase();
    draw_header(cols);
    draw_events(rows, cols);
    draw_footer(rows, cols);
    refresh();
}

/* ============================================================================
 * Info Popup using ncurses window
 * ============================================================================ */
static void show_info_popup(void)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int box_w = 50;
    int box_h = 16;
    int start_r = (rows - box_h) / 2;
    int start_c = (cols - box_w) / 2;
    if (start_r < 1) start_r = 1;
    if (start_c < 1) start_c = 1;

    WINDOW *popup = newwin(box_h, box_w, start_r, start_c);
    wbkgd(popup, COLOR_PAIR(CP_POPUP_BG));
    box(popup, 0, 0);

    /* Content lines: {text, color_pair} */
    struct { const char *text; int cp; int attr; } lines[] = {
        { "SMTP CONNECTION MONITOR v1.0",  CP_POPUP_TITLE, A_BOLD },
        { "",                              CP_POPUP_BG,    0 },
        { "-------------------------------", CP_POPUP_SEP,  0 },
        { "",                              CP_POPUP_BG,    0 },
        { "By Managed Server S.r.l.",      CP_POPUP_BG,    A_BOLD },
        { "Performance Managed Hosting",   CP_POPUP_BG,    A_BOLD },
        { "",                              CP_POPUP_BG,    0 },
        { "https://managedserver.it",      CP_POPUP_URL,   0 },
        { "info@managedserver.it",         CP_POPUP_URL,   0 },
        { "",                              CP_POPUP_BG,    0 },
        { "-------------------------------", CP_POPUP_SEP,  0 },
        { "",                              CP_POPUP_BG,    0 },
        { "Press any key to close",        CP_POPUP_DIM,   0 },
        { NULL, 0, 0 }
    };

    int inner_w = box_w - 2;
    for (int i = 0; lines[i].text; i++) {
        int len = (int)strlen(lines[i].text);
        int pad = (inner_w - len) / 2;
        if (pad < 0) pad = 0;

        wattron(popup, COLOR_PAIR(lines[i].cp) | lines[i].attr);
        mvwprintw(popup, i + 1, pad + 1, "%s", lines[i].text);
        wattroff(popup, COLOR_PAIR(lines[i].cp) | lines[i].attr);
    }

    wrefresh(popup);

    /* Wait for any key */
    nodelay(stdscr, FALSE);
    wgetch(popup);
    nodelay(stdscr, TRUE);

    delwin(popup);
    g_needs_redraw = 1;
}

/* ============================================================================
 * Signal handler
 * ============================================================================ */
static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */
int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0)
            g_mode = 1;
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            g_mode = 2;
            g_logfile = fopen(argv[++i], "a");
            if (!g_logfile) { perror("fopen"); return 1; }
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  -l          Log to stdout\n");
            printf("  -f <file>   Log to file\n");
            printf("  -h          Show this help\n");
            printf("\nWithout options: interactive mode (ncurses TUI)\n");
            return 0;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: root privileges required.\n");
        return 1;
    }

    memset(&g_events, 0, sizeof(g_events));
    pthread_mutex_init(&g_events.lock, NULL);
    memset(g_cache, 0, sizeof(g_cache));

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Add audit rules via auditctl */
    audit_add_rules();

    /* Start log reader thread */
    pthread_t reader;
    pthread_create(&reader, NULL, log_reader_thread, NULL);

    /* Start RDNS resolver thread */
    pthread_t rdns_thread;
    pthread_create(&rdns_thread, NULL, rdns_resolver_thread, NULL);

    if (g_mode == 0) {
        /* Interactive ncurses mode */
        setlocale(LC_ALL, "");
        initscr();
        cbreak();
        noecho();
        nonl();
        nodelay(stdscr, TRUE);
        keypad(stdscr, TRUE);
        curs_set(0);

        if (has_colors())
            init_colors();

        while (g_running) {
            if (g_needs_redraw || !g_paused) {
                draw_ui();
                g_needs_redraw = 0;
            }

            int ch = getch();
            if (ch == ERR) {
                napms(100);
                if (!g_paused) g_needs_redraw = 1;
                continue;
            }

            int total = event_count();
            int rows, cols;
            getmaxyx(stdscr, rows, cols);
            (void)cols;
            int data_rows = rows - 7;

            switch (ch) {
            case 'q': case 'Q':
                g_running = 0;
                break;
            case 'p': case 'P':
                g_paused = !g_paused;
                if (!g_paused) g_scroll_offset = 0;
                g_needs_redraw = 1;
                break;
            case 'c': case 'C':
                event_clear();
                g_scroll_offset = 0;
                break;
            case 'r': case 'R':
                g_show_rdns = !g_show_rdns;
                g_needs_redraw = 1;
                break;
            case 'i': case 'I':
                show_info_popup();
                break;
            case KEY_UP:
                if (g_paused) {
                    int mx = total - data_rows;
                    if (mx < 0) mx = 0;
                    if (g_scroll_offset < mx) g_scroll_offset++;
                    g_needs_redraw = 1;
                }
                break;
            case KEY_DOWN:
                if (g_paused && g_scroll_offset > 0) {
                    g_scroll_offset--;
                    g_needs_redraw = 1;
                }
                break;
            case KEY_PPAGE:
                if (g_paused) {
                    g_scroll_offset += data_rows;
                    int mx = total - data_rows;
                    if (mx < 0) mx = 0;
                    if (g_scroll_offset > mx) g_scroll_offset = mx;
                    g_needs_redraw = 1;
                }
                break;
            case KEY_NPAGE:
                if (g_paused) {
                    g_scroll_offset -= data_rows;
                    if (g_scroll_offset < 0) g_scroll_offset = 0;
                    g_needs_redraw = 1;
                }
                break;
            case KEY_HOME:
                g_paused = 1;
                g_scroll_offset = total - data_rows;
                if (g_scroll_offset < 0) g_scroll_offset = 0;
                g_needs_redraw = 1;
                break;
            case KEY_END:
                g_paused = 0;
                g_scroll_offset = 0;
                g_needs_redraw = 1;
                break;
            case KEY_RESIZE:
                g_needs_redraw = 1;
                break;
            }
        }

        endwin();
    } else {
        if (g_mode == 1)
            fprintf(stderr, "SMTP Monitor started. Press Ctrl+C to exit.\n");
        else
            fprintf(stderr, "SMTP Monitor logging to %s. Press Ctrl+C to exit.\n", argv[2]);

        while (g_running)
            sleep(1);
    }

    g_running = 0;
    pthread_join(reader, NULL);
    pthread_join(rdns_thread, NULL);

    audit_del_rules();
    if (g_logfile) fclose(g_logfile);

    fprintf(stderr, "Monitor stopped. Audit rules removed.\n");
    return 0;
}

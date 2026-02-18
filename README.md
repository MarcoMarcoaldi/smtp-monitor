# SMTP Connection Monitor

**Real-time monitoring of outbound SMTP connections on Linux servers.**

Identifies which system user and process is making SMTP connections — essential for tracking down compromised websites sending spam on shared hosting environments.

<img width="1911" height="1088" alt="image" src="https://github.com/user-attachments/assets/ce13f68d-9e95-4466-b54d-f7f51508d7f6" />


---

## The Problem

On shared hosting servers (LAMP, LEMP, cPanel, Plesk, DirectAdmin, or custom setups), one of the most common and damaging security incidents is a **compromised website silently sending spam**. A single hacked PHP script — often an outdated WordPress plugin, a vulnerable contact form, or an uploaded webshell — can generate thousands of outbound emails, leading to:

- **IP blacklisting** across major RBLs (Spamhaus, Barracuda, SORBS), affecting every legitimate customer on the server.
- **Reputation damage** to the server's IP addresses and entire IP ranges.
- **Resource exhaustion** — spam scripts consume CPU, memory, and network bandwidth.
- **Potential legal liability** under anti-spam legislation (CAN-SPAM, GDPR).
- **Service suspension** by upstream providers and data centers.

The challenge is **attribution**. On a busy shared hosting server running hundreds of websites under different system users, each with their own PHP-FPM pool, identifying *which specific user account* is generating SMTP traffic is surprisingly difficult:

- Traditional mail logs (`/var/log/maillog`) show the envelope sender but not always the originating system user.
- Firewall logs capture connections but lack process-level detail.
- Running `tcpdump` or `strace` on production servers is invasive, resource-heavy, and impractical at scale.
- PHP's `mail()` function goes through the local MTA, adding indirection that obscures the source.
- Direct SMTP connections from PHP (via PHPMailer, SwiftMailer, or `fsockopen`) bypass the local MTA entirely, leaving no trace in mail logs.

**SMTP Connection Monitor** solves this by leveraging the Linux kernel's audit subsystem to intercept every `connect()` syscall destined for SMTP ports, correlating it in real-time with the originating process, user, and working directory.

---

## How It Works

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        GNU/Linux Kernel                      │
│                                                              │
│  connect() syscall ──► audit subsystem ──► audit.log         │
│                        (via auditctl rules)                  │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               │  inotify (IN_MODIFY)
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                     smtp-monitor (C)                         │
│                                                              │
│  ┌──────────────┐  ┌─────────────────┐  ┌──────────────────┐ │
│  │ Log Reader   │  │ SYSCALL/SOCKADDR│  │  RDNS Resolver   │ │
│  │ Thread       ├──► Correlator      │  │  Thread (async)  │ │
│  │ (inotify)    │  │ (serial-based)  │  │  (getnameinfo)   │ │
│  └──────────────┘  └───────┬─────────┘  └──────────────────┘ │
│                            │                                 │
│                     ┌──────▼───────┐                         │
│                     │ Event Buffer │                         │
│                     │ (circular,   │                         │
│                     │  10K events) │                         │
│                     └──────┬───────┘                         │
│                            │                                 │
│              ┌─────────────┼────────────┐                    │
│              ▼             ▼            ▼                    │
│         Interactive     stdout       File                    │
│         TUI (ncurses   logging     logging                   │
│          style)                                              │
└──────────────────────────────────────────────────────────────┘

```

### Technical Deep Dive

#### 1. Audit Rule Injection

On startup, the program adds audit rules via `auditctl` to trace the `connect()` syscall (syscall 42 on x86_64, both 32-bit and 64-bit ABIs):

```bash
auditctl -a always,exit -F arch=b64 -S connect -k smtp_mon_<PID>
auditctl -a always,exit -F arch=b32 -S connect -k smtp_mon_<PID>
```

The rules are tagged with a unique key containing the monitor's PID. On exit (including `SIGINT`/`SIGTERM`), the rules are automatically removed. This ensures a clean slate even if the monitor is interrupted.

#### 2. Log Parsing via inotify

Rather than opening a direct netlink socket to the audit subsystem (which would conflict with `auditd` and potentially disrupt existing audit infrastructure), the monitor reads `/var/log/audit/audit.log` in real-time using Linux's `inotify` API, similar to `tail -F` but implemented efficiently in C.

This approach:
- **Fully coexists with auditd** — no need to stop or restart the audit daemon.
- **Handles log rotation** — monitors the directory for `IN_CREATE` events and automatically reopens the log file when it detects an inode change.
- **Seeks to end on startup** — only captures events that occur while the monitor is running, avoiding historical noise.

#### 3. SYSCALL-SOCKADDR Correlation

The Linux audit subsystem emits multiple record types for a single event, linked by a common serial number in the `msg=audit(TIMESTAMP:SERIAL)` field:

- **`type=SYSCALL`** — contains the process metadata: `pid`, `uid`, `euid`, `exe`, `comm`.
- **`type=SOCKADDR`** — contains the raw socket address (`saddr`) with the destination IP and port.
- **`type=CWD`** — contains the working directory of the process.

The monitor maintains a **circular cache of 4,096 SYSCALL entries** and correlates them with incoming SOCKADDR records using the audit serial number. When a SOCKADDR record arrives, the monitor:

1. Decodes the hex-encoded `saddr` field to extract the address family, destination port, and IP.
2. Filters for SMTP ports only (25, 465, 587, 2525).
3. Looks up the matching SYSCALL record in the cache to retrieve the process information.
4. Resolves the effective UID (`euid`) to a username via `getpwuid()`.

#### 4. Effective UID Resolution

On shared hosting servers, PHP-FPM pools typically run under the website owner's system user (e.g., `example.com` with UID 1039). The monitor extracts the `euid` (effective UID) from the audit SYSCALL record rather than the `uid` (real UID), which correctly identifies the PHP-FPM worker's actual user context.

The field parser uses **whole-word matching** to avoid false matches — for example, searching for `euid=` must not match within `fsuid=` or `suid=`. The parser verifies that the character preceding the field name is a word boundary (space, `)`, or `:`).

As a fallback, if the `euid` is 0 (root), the monitor reads `/proc/PID/status` directly to obtain the actual effective UID, handling edge cases where the audit record might reflect the master process rather than the worker.

#### 5. Socket Address Decoding

The `saddr` field in audit SOCKADDR records is a hex-encoded raw `sockaddr` structure:

**IPv4 (AF_INET = `0200`):**
```
saddr=0200PPPPAAAAAAAA00000000000000
       ││  ││  ││││││││
       ││  ││  └┴┴┴┴┴┴┴─ IP address (4 bytes)
       ││  └┴──────────── Port (2 bytes, network order)
       └┴────────────────  Address family (0x0200 = AF_INET)
```

**IPv6 (AF_INET6 = `0A00`):**
```
saddr=0A00PPPP00000000AAAAAAAAAAAAAAAAAAAAAAAAAAAA0000
       ││  ││          ││││││││││││││││││││││││││││
       ││  ││          └┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴── IPv6 address (16 bytes)
       ││  └┴──────────── Port (2 bytes, network order)
       └┴────────────────  Address family (0x0A00 = AF_INET6)
```

The monitor decodes both IPv4 and IPv6 addresses, filters out localhost connections (`127.0.0.1`, `::1`), and formats the output using `inet_ntop()`.

#### 6. Asynchronous Reverse DNS

When enabled via the `[R]` toggle, reverse DNS resolution runs in a **dedicated background thread** to avoid blocking the UI or event processing. Results are cached in a thread-safe DNS cache (512 entries) so each unique IP is resolved only once. The resolver uses `getnameinfo()` with `NI_NAMEREQD` to obtain PTR records.

#### 7. Thread Safety

The program uses three threads:
- **Main thread** — handles terminal I/O and UI rendering.
- **Log reader thread** — reads and parses the audit log.
- **RDNS resolver thread** — resolves reverse DNS in the background.

All shared data structures (event buffer, SYSCALL cache, DNS cache) are protected by `pthread_mutex_t` locks.

---

## Monitored Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 25   | SMTP     | Standard SMTP relay (often blocked by ISPs) |
| 465  | SMTPS    | SMTP over implicit TLS |
| 587  | Submission | SMTP submission with STARTTLS (most common for authenticated sending) |
| 2525 | SMTP-ALT | Alternative SMTP port (used by some providers) |

---

## Requirements

- **Linux** with kernel audit subsystem enabled (standard on RHEL, CentOS, AlmaLinux, Rocky Linux, Debian, Ubuntu)
- **auditd** running (the monitor coexists with it)
- **auditctl** available in PATH
- **ncurses** development library (`ncurses-devel` on RHEL/AlmaLinux, `libncurses-dev` on Debian/Ubuntu)
- **Root privileges** (required for audit rule management and `/proc` access)
- **GCC** for compilation
- **pthreads** (standard on all Linux distributions)

No other external dependencies beyond libc, libncurses, and libpthread.

### Verified On

- AlmaLinux 8 / 9 / 10
- Rocky Linux 8 / 9 / 10
- CentOS 7 / 8
- RHEL 7 / 8 / 9 / 10
- Debian 11 / 12
- Ubuntu 22.04 / 24.04

---

## Installation

```bash
# Clone the repository
git clone https://github.com/MarcoMarcoaldi/smtp-monitor.git
cd smtp-monitor

# Install build dependencies
# RHEL / AlmaLinux / Rocky / CentOS:
sudo dnf install gcc ncurses-devel
# Debian / Ubuntu:
sudo apt install gcc libncurses-dev

# Compile
gcc -O2 -o smtp-monitor smtp-monitor.c -lncurses -lpthread

# Optionally install system-wide
sudo cp smtp-monitor /usr/local/bin/
```

---

## Usage

### Interactive Mode (default)

```bash
sudo ./smtp-monitor
```

Launches a full-screen terminal UI with real-time event display, color-coded by protocol.

### Log to stdout

```bash
sudo ./smtp-monitor -l
```

Outputs each SMTP connection event as a single line to stdout. Useful for piping to other tools:

```bash
sudo ./smtp-monitor -l | grep "php-fpm"
sudo ./smtp-monitor -l | tee /var/log/smtp-connections.log
```

### Log to file

```bash
sudo ./smtp-monitor -f /var/log/smtp-connections.log
```

Writes events directly to the specified file. Ideal for long-running background monitoring:

```bash
sudo nohup ./smtp-monitor -f /var/log/smtp-connections.log &
```

### Output Format (log mode)

```
[2026-02-18 13:39:28] USER=idealufficio.it                PID=1087389  PROC=php-fpm                  PORT=587   DST=2a00:1450:4001:c21::6c                CWD=/home/idealufficio.it/htdocs
[2026-02-18 13:39:28] USER=example.com                    PID=1087401  PROC=php-fpm                  PORT=465   DST=2a01:4f8:1c1c:5870::1                 CWD=/home/example.com/htdocs
[2026-02-18 13:40:15] USER=root                           PID=29441    PROC=postfix/smtp             PORT=25    DST=5.75.214.156                          CWD=/var/spool/postfix
```

---

## Interactive Controls

| Key | Action |
|-----|--------|
| **P** | Pause / Resume live display |
| **C** | Clear all events from screen |
| **R** | Toggle reverse DNS column (resolved asynchronously) |
| **I** | Show Info popup (version, credits) |
| **↑ / ↓** | Scroll up/down (when paused) |
| **PgUp / PgDn** | Page up/down (when paused) |
| **Home** | Jump to oldest event (pauses display) |
| **End** | Jump to latest event (resumes live) |
| **Q** | Quit (automatically removes audit rules) |

---

## Displayed Columns

| Column | Description |
|--------|-------------|
| **TIMESTAMP** | Date and time the connection was detected |
| **USER** | System username of the process (resolved from effective UID) |
| **PID** | Process ID that initiated the `connect()` syscall |
| **PROCESS** | Executable name (e.g., `php-fpm`, `postfix/smtp`, `python3`) |
| **PORT** | Destination SMTP port number |
| **PROTO** | Protocol label: SMTP (25), SMTPS (465), SUBMISSION (587), SMTP-ALT (2525) |
| **DESTINATION** | Remote IP address (IPv4 or IPv6) |
| **RDNS** | Reverse DNS hostname (shown when `[R]` is enabled) |
| **CWD** | Working directory of the process at connection time |

---

## Use Cases

### Finding a Spam Source on Shared Hosting

```bash
# Start monitoring
sudo ./smtp-monitor -l | tee /tmp/smtp.log

# Wait for spam activity, then analyze
sort /tmp/smtp.log | awk '{print $2}' | sort | uniq -c | sort -rn | head -20
```

This quickly reveals which user accounts are generating the most SMTP connections.

### Monitoring Specific Users

```bash
sudo ./smtp-monitor -l | grep "USER=compromised-site.com"
```

### Integrating with Fail2ban

Create a Fail2ban filter to automatically block users exceeding SMTP connection thresholds:

```bash
# Log to a dedicated file
sudo ./smtp-monitor -f /var/log/smtp-monitor.log

# Then create a Fail2ban jail watching that log
```

### Cron-based Reporting

```bash
# Run for 1 hour and email a summary
timeout 3600 /usr/local/bin/smtp-monitor -f /tmp/smtp-hourly.log
cat /tmp/smtp-hourly.log | mail -s "SMTP Activity Report" admin@example.com
```

### Logrotate Integration

```
# /etc/logrotate.d/smtp-monitor
/var/log/smtp-connections.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```

---

## Performance Considerations

- **Minimal CPU overhead** — the monitor sleeps on `inotify` and only wakes when new audit log data is written. No polling loops.
- **Memory footprint** — approximately 15-20 MB resident, dominated by the 10,000-event circular buffer and the SYSCALL correlation cache.
- **Audit impact** — adding a `connect()` audit rule does add overhead to every `connect()` syscall system-wide. On busy servers with hundreds of concurrent connections, this is measurable but typically under 1-2% CPU overhead. The rule is automatically removed on exit.
- **RDNS resolution** — runs asynchronously and never blocks event capture. DNS queries use a cache to avoid redundant lookups. Keep in mind that enabling RDNS on a server handling thousands of unique IPs will generate additional DNS traffic.

---

## How It Compares

| Approach | Identifies User | Real-time | No PHP Changes | Coexists with auditd | Low Overhead |
|----------|:-:|:-:|:-:|:-:|:-:|
| **smtp-monitor** | ✅ | ✅ | ✅ | ✅ | ✅ |
| Mail log parsing | ❌ | ⚠️ | ✅ | ✅ | ✅ |
| `tcpdump` / `ngrep` | ❌ | ✅ | ✅ | ✅ | ❌ |
| `strace -p` | ✅ | ✅ | ✅ | ✅ | ❌ |
| PHP `auto_prepend_file` | ✅ | ✅ | ❌ | ✅ | ⚠️ |
| eBPF / bpftrace | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Cleanup

The monitor automatically removes its audit rules on normal exit or `SIGINT`/`SIGTERM`. If the process is killed with `SIGKILL` or crashes, remove orphaned rules manually:

```bash
# List rules
auditctl -l | grep smtp_mon

# Remove them
auditctl -l | grep smtp_mon | sed 's/-a /-d /' | while read -r rule; do eval "auditctl $rule"; done
```

---

## Limitations

- **Requires root** — audit rule management and `/proc` access need root privileges or `CAP_AUDIT_CONTROL` + `CAP_AUDIT_READ` capabilities.
- **Cannot identify the specific PHP script** — PHP-FPM reads and closes the `.php` file before executing the code, so the script path is not available in `/proc/PID/fd` at connection time. The CWD column narrows it down to the website's document root.
- **Audit log volume** — on very busy servers, tracing all `connect()` syscalls generates significant audit log volume. The monitor only processes SMTP-related events, but `auditd` still writes all connection events to disk. Monitor your audit log size and rotation settings.
- **Short-lived processes** — if a process calls `connect()` and exits before the monitor processes the audit event, the `/proc/PID` fallback for UID resolution will fail. The audit record's `euid` field is still used as the primary source.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Credits

Developed by **[Managed Server S.r.l.](https://managedserver.it)** — Performance Managed Hosting.

Built from real-world experience managing shared hosting infrastructure and dealing with compromised websites on a daily basis.

---

## Contributing

Issues and pull requests are welcome. If you're running a hosting environment and have edge cases or feature requests, please open an issue.

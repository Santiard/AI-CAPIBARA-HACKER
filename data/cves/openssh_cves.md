# Technical Security Advisories: OpenSSH & Secure Shell

## 1. OpenSSH Server RegreSSHion Remote Code Execution (CVE-2024-6387)
- **Service**: openssh
- **Affected Versions**: OpenSSH 8.5p1 through 9.7p1 (on glibc-based Linux systems)
- **CVSS v3 Score**: 8.1 (HIGH) - `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE**: CWE-362 (Race Condition)

### Technical Analysis
OpenSSH `sshd` contains a signal handler race condition in the `SIGALRM` handler. If a client does not complete authentication within the timeframe specified by `LoginGraceTime` (default 120 seconds), `sshd`'s `SIGALRM` handler is invoked.
This handler calls `syslog()`, which is not async-signal-safe. On glibc systems, an attacker can manipulate heap state via timed packet delivery, exploiting heap corruption in the syslog call to execute arbitrary shellcode as root.

### Remediation
1. Update OpenSSH to version 9.8p1 or newer.
2. Temporary workaround in `/etc/ssh/sshd_config`:
```sshd
LoginGraceTime 0
```
*Note: Setting LoginGraceTime to 0 prevents the SIGALRM race condition, but may expose the server to connection exhaustion DoS.*

---

## 2. OpenSSH User Enumeration via Timing (CVE-2018-15473)
- **Service**: openssh
- **Affected Versions**: OpenSSH versions up to 7.7
- **CVSS v3 Score**: 5.3 (MEDIUM) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **CWE**: CWE-200 (Information Disclosure)

### Technical Analysis
OpenSSH versions before 7.7 improperly format authentication responses when invalid usernames are supplied, returning authentication failure earlier than for valid usernames. This allows unauthenticated remote attackers to enumerate valid usernames.

### Remediation
Upgrade OpenSSH to version 7.8 or higher.

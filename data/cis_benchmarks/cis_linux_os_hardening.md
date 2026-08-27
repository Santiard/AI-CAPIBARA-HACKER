# CIS Linux Operating System Benchmark & OS Hardening Guide

## Overview
Comprehensive system-level hardening guidelines for Linux distributions (Debian, Ubuntu, RHEL, Rocky).

---

### Rule CIS-LNX-1.1: Restrict Shadow and Passwd File Permissions
- **Service**: linux
- **Severity**: HIGH
- **Remediation**:
  ```bash
  chown root:root /etc/passwd && chmod 644 /etc/passwd
  chown root:shadow /etc/shadow && chmod 640 /etc/shadow
  chown root:root /etc/group && chmod 644 /etc/group
  chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
  ```

---

### Rule CIS-LNX-1.2: Kernel Network Parameter Hardening (`/etc/sysctl.d/99-security.conf`)
- **Service**: linux
- **Severity**: HIGH
- **Remediation**:
  ```ini
  # Disable IP packet forwarding
  net.ipv4.ip_forward = 0
  # Disable ICMP redirect acceptance
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.default.accept_redirects = 0
  # Enable SYN Flood protection
  net.ipv4.tcp_syncookies = 1
  # Log martian packets
  net.ipv4.conf.all.log_martians = 1
  # Ignore ICMP echo broadcasts
  net.ipv4.icmp_echo_ignore_broadcasts = 1
  # Address space layout randomization (ASLR)
  kernel.randomize_va_space = 2
  ```

---

### Rule CIS-LNX-1.3: Enforce Default Firewall Policy (UFW / iptables)
- **Service**: linux
- **Severity**: HIGH
- **Remediation**:
  ```bash
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp comment 'SSH restricted'
  ufw enable
  ```

---

### Rule CIS-LNX-1.4: Disable Legacy and Insecure Services (Telnet, rsh, rlogin, FTP)
- **Service**: linux
- **Severity**: HIGH
- **Remediation**:
  ```bash
  systemctl stop telnet.socket rsh.socket rlogin.socket vsftpd
  systemctl disable telnet.socket rsh.socket rlogin.socket vsftpd
  ```

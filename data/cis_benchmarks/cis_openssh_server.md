# CIS OpenSSH Server Benchmark & Remediation Guide

## Overview
Hardening controls for OpenSSH Server daemon (`sshd`) across Linux infrastructure.

---

### Rule CIS-SSH-1.1: Disable Direct Root Login (`PermitRootLogin`)
- **Service**: openssh
- **Severity**: HIGH
- **Rationale**: Direct root access over SSH facilitates brute-force attacks and prevents non-repudiation in audit trails.
- **Audit Command**:
  ```bash
  sshd -T | grep -i permitrootlogin
  ```
- **Remediation (`/etc/ssh/sshd_config`)**:
  ```sshd
  PermitRootLogin no
  ```

---

### Rule CIS-SSH-1.2: Enforce Public Key Authentication Only
- **Service**: openssh
- **Severity**: HIGH
- **Rationale**: Password authentication is vulnerable to credential stuffing, dictionary attacks, and interception.
- **Remediation (`/etc/ssh/sshd_config`)**:
  ```sshd
  PubkeyAuthentication yes
  PasswordAuthentication no
  PermitEmptyPasswords no
  KbdInteractiveAuthentication no
  ```

---

### Rule CIS-SSH-1.3: Limit Authentication Attempts and Idle Timeouts
- **Service**: openssh
- **Severity**: MEDIUM
- **Remediation (`/etc/ssh/sshd_config`)**:
  ```sshd
  MaxAuthTries 3
  LoginGraceTime 60
  ClientAliveInterval 300
  ClientAliveCountMax 2
  ```

---

### Rule CIS-SSH-1.4: Disable X11 and Agent Forwarding
- **Service**: openssh
- **Severity**: MEDIUM
- **Rationale**: Disabling unused forwarding prevents pivot attacks from compromised accounts.
- **Remediation (`/etc/ssh/sshd_config`)**:
  ```sshd
  X11Forwarding no
  AllowAgentForwarding no
  AllowTcpForwarding no
  ```

---

### Rule CIS-SSH-1.5: Modern Robust Key Exchange, Ciphers and MACs
- **Service**: openssh
- **Severity**: HIGH
- **Remediation (`/etc/ssh/sshd_config`)**:
  ```sshd
  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  ```

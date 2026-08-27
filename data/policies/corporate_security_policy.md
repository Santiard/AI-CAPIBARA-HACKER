# Corporate Cybersecurity & Compliance Policy Standard (POL-SEC-2026)

## 1. Scope & Purpose
This policy establishes mandatory cybersecurity controls, port exposure standards, and vulnerability remediation Service Level Agreements (SLAs) for all production, staging, and development infrastructure within the organization.

---

## 2. Vulnerability Remediation SLAs
All security vulnerabilities discovered during network scans, automated multi-agent audits, or penetration tests must be remediated according to their CVSS v3 score severity:

| Severity Rating | CVSS v3 Score | Maximum Remediation SLA | Mandatory Action |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | `9.0 - 10.0` | **24 Hours** | Immediate emergency patch, service isolation or WAF mitigation rule. |
| **HIGH** | `7.0 - 8.9` | **7 Calendar Days** | Expedited patching or configuration hardening. |
| **MEDIUM** | `4.0 - 6.9` | **30 Calendar Days** | Scheduled maintenance window upgrade. |
| **LOW** | `0.1 - 3.9` | **90 Calendar Days** | Routine backlog review. |

---

## 3. Network Port & Service Exposure Rules

### 3.1 Prohibited Legacy Protocols
- **Telnet (Port 23)**: Strictly prohibited. Cleartext credentials are not permitted on any organizational subnet.
- **FTP (Port 21)**: Unencrypted FTP is prohibited in production. Use SFTP (Port 22) or FTPS (TLS).
- **RSH / RLOGIN / RCP (Ports 512, 513, 514)**: Strictly disabled.
- **SMBv1 (Port 445)**: Completely forbidden due to known remote exploit vectors (EternalBlue).

### 3.2 Web & HTTP Services (Ports 80 / 443)
- Plaintext HTTP (Port 80) must unconditionally redirect with HTTP 301 to HTTPS (Port 443).
- SSLv3, TLS 1.0, and TLS 1.1 must be disabled. Only TLS 1.2 and TLS 1.3 are authorized.
- Web servers must disable banner exposure (`ServerTokens Prod`, `server_tokens off`).

### 3.3 Remote Administration & SSH (Port 22)
- Direct root login (`PermitRootLogin no`) is strictly prohibited.
- Password-based authentication (`PasswordAuthentication no`) is disallowed; ed25519 or RSA-4096 SSH keys with passphrase are required.
- Multi-Factor Authentication (MFA) is mandatory for external bastion hosts.

### 3.4 Database Isolation (MySQL 3306, PostgreSQL 5432, Redis 6379)
- Databases must **never** be exposed directly to public subnets (`0.0.0.0/0`).
- All database daemons must bind to internal RFC1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or localhost (`127.0.0.1`).
- Redis must have authentication (`requirepass`) enabled and dangerous commands renamed or disabled.

---

## 4. Ethical Multi-Agent Security Audit Authorization
Automated security audit agents (such as **AI-CAPIBARA-HACKER**) are authorized to:
1. Parse authorized Nmap port and service scans.
2. Query vulnerability intelligence databases (CVE/NVD) for detected service versions.
3. Contrast detected configurations against CIS Hardening Benchmarks.
4. Generate technical remediation playbooks and executive risk summaries.
*Note: Offensive exploitation or denial-of-service payloads are strictly out of scope without explicit written CISO authorization.*

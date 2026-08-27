# CIS Apache HTTP Server Benchmark & Remediation Guide

## Overview
This document specifies standard configuration hardening controls based on the Center for Internet Security (CIS) Apache HTTP Server Benchmark.

---

### Rule CIS-APA-1.1: Restrict Root Directory Access
- **Service**: apache
- **Severity**: HIGH
- **Rationale**: By default, Apache should deny access to the entire root filesystem, granting granular access only to explicitly declared document roots.
- **Audit Command**:
  ```bash
  grep -A 4 "<Directory />" /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf
  ```
- **Remediation Configuration**:
  ```apache
  <Directory />
      AllowOverride None
      Require all denied
  </Directory>
  ```

---

### Rule CIS-APA-1.2: Disable Directory Indexing and Traversal Options
- **Service**: apache
- **Severity**: MEDIUM
- **Rationale**: Automatic directory browsing (`Indexes`) reveals sensitive files and backup assets to unauthorized visitors.
- **Remediation Configuration**:
  ```apache
  <Directory "/var/www/html">
      Options -Indexes -FollowSymLinks +SymLinksIfOwnerMatch
      AllowOverride None
      Require all granted
  </Directory>
  ```

---

### Rule CIS-APA-1.3: Minimize Information Disclosure (ServerTokens & ServerSignature)
- **Service**: apache
- **Severity**: LOW
- **Rationale**: Exposing specific web server version and OS banners aids attackers during automated reconnaissance.
- **Remediation Configuration**:
  ```apache
  ServerTokens Prod
  ServerSignature Off
  TraceEnable Off
  ```

---

### Rule CIS-APA-1.4: Enforce TLS 1.2+ and Secure Cipher Suites
- **Service**: apache
- **Severity**: HIGH
- **Rationale**: Legacy SSLv3, TLS 1.0, and weak CBC ciphers are vulnerable to cryptographic downgrade attacks (e.g. POODLE, BEAST).
- **Remediation Configuration**:
  ```apache
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
  SSLHonorCipherOrder on
  ```

---

### Rule CIS-APA-1.5: Security Response Headers (HSTS, CSP, X-Frame-Options)
- **Service**: apache
- **Severity**: MEDIUM
- **Remediation Configuration**:
  ```apache
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-XSS-Protection "1; mode=block"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  ```

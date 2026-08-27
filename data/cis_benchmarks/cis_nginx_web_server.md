# CIS Nginx Web Server Benchmark & Hardening Guide

## Overview
Hardening recommendations for Nginx reverse proxies, HTTP servers, and load balancers.

---

### Rule CIS-NGX-1.1: Disable Version Emission (`server_tokens`)
- **Service**: nginx
- **Severity**: LOW
- **Remediation (`/etc/nginx/nginx.conf`)**:
  ```nginx
  http {
      server_tokens off;
  }
  ```

---

### Rule CIS-NGX-1.2: Buffer Limits and DoS Mitigation
- **Service**: nginx
- **Severity**: MEDIUM
- **Remediation**:
  ```nginx
  client_body_buffer_size 16k;
  client_header_buffer_size 1k;
  client_max_body_size 8M;
  large_client_header_buffers 2 1k;
  client_body_timeout 10;
  client_header_timeout 10;
  keepalive_timeout 15;
  send_timeout 10;
  ```

---

### Rule CIS-NGX-1.3: Rate Limiting on Authentication & Sensitive Endpoints
- **Service**: nginx
- **Severity**: HIGH
- **Remediation**:
  ```nginx
  limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;

  location /login/ {
      limit_req zone=login_limit burst=10 nodelay;
      proxy_pass http://backend_app;
  }
  ```

---

### Rule CIS-NGX-1.4: Strict SSL/TLS Profile and Modern Ciphers
- **Service**: nginx
- **Severity**: HIGH
- **Remediation**:
  ```nginx
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  ```

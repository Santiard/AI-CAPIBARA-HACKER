# Technical Security Advisories: Apache HTTP Server & Modules

## 1. Apache HTTP Server Path Traversal and RCE (CVE-2021-41773)
- **Service**: apache
- **Affected Versions**: Apache HTTP Server 2.4.49
- **CVSS v3 Score**: 9.8 (CRITICAL) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

### Technical Analysis
Apache HTTP Server version 2.4.49 introduced an optimization in the `ap_normalize_path` function within `server/util.c`. The normalization routine fails to properly resolve URL-encoded path segments using `.%2e` (dot-percent-2-e).
When a request such as `GET /icons/.%2e/.%2e/.%2e/etc/passwd` is received and the directory alias does not have `Require all denied` enforced, Apache allows reading arbitrary files outside the document root. Furthermore, if `mod_cgi` or `cgid` is enabled, an attacker can execute binaries on the target system by POSTing data to `/cgi-bin/.%2e/.%2e/bin/sh`.

### Verification Steps
```bash
curl -s --path-as-is "http://TARGET:80/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"
```

### Remediation
1. Update Apache HTTP Server immediately to version 2.4.51 or later.
2. In `httpd.conf` / `apache2.conf`, enforce restrictive root directory permissions:
```apache
<Directory />
    AllowOverride None
    Require all denied
</Directory>
```

---

## 2. Apache HTTP Server Path Traversal and RCE Bypass (CVE-2021-42013)
- **Service**: apache
- **Affected Versions**: Apache HTTP Server 2.4.49, 2.4.50
- **CVSS v3 Score**: 9.8 (CRITICAL) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE**: CWE-22

### Technical Analysis
The fix implemented in 2.4.50 was incomplete, as double URL-encoding (`%%32%65%%32%65`) bypassed the newly added checks. This enabled the same path traversal and remote code execution vector.

### Remediation
Apply vendor patch 2.4.51+ or remove unused CGI modules (`a2dismod cgi cgid`).

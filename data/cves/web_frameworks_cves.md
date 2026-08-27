# Technical Security Advisories: Web Frameworks, Proxies & Runtimes

## 1. Apache Log4j2 JNDI Remote Code Execution (Log4Shell - CVE-2021-44228)
- **Service**: log4j
- **Affected Versions**: Log4j 2.0-beta9 to 2.14.1
- **CVSS v3 Score**: 10.0 (CRITICAL) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **CWE**: CWE-502 (Deserialization of Untrusted Data)

### Technical Analysis
Log4j2 includes support for Message Lookups including JNDI (`Java Naming and Directory Interface`). When logging untrusted input (e.g. `User-Agent`, request headers, form fields), strings matching `${jndi:ldap://...}` or `${jndi:rmi://...}` trigger outbound network calls to retrieve and instantiate remote Java classes, executing attacker code.

### Remediation
- Upgrade to Log4j 2.17.1+.
- Set JVM argument: `-Dlog4j2.formatMsgNoLookups=true`.
- Remove `JndiLookup` class: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`.

---

## 2. Apache Tomcat AJP Ghostcat File Read & RCE (CVE-2020-1938)
- **Service**: tomcat
- **Affected Versions**: Tomcat 7.0.0 to 7.0.99, 8.5.0 to 8.5.50, 9.0.0 to 9.0.30
- **CVSS v3 Score**: 9.8 (CRITICAL) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CWE**: CWE-200 / CWE-94

### Technical Analysis
Apache Tomcat by default bound the AJP connector to port 8009 on `0.0.0.0` with default trust. Attackers connecting directly to AJP can read sensitive files inside web applications (including config files and credentials) and execute arbitrary code via JSP file inclusion if uploads are allowed.

### Remediation
- Upgrade to Tomcat 9.0.31+, 8.5.51+, or 7.0.100+.
- In `conf/server.xml`, disable the AJP connector if unused, or set `secretRequired="true"` and `secret="<STRONG_PASSWORD>"`.

---

## 3. Nginx DNS Resolver Buffer Overwrite (CVE-2021-23017)
- **Service**: nginx
- **Affected Versions**: Nginx 0.6.18 through 1.20.0
- **CVSS v3 Score**: 7.7 (HIGH) - `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

### Technical Analysis
An off-by-one bug in the DNS resolver module when processing DNS CNAME responses can overwrite 1 byte of heap memory, triggering a worker process crash or arbitrary code execution in setups where dynamic proxy pass domains rely on the `resolver` directive.

### Remediation
Update Nginx to version 1.20.1 or 1.21.0+.

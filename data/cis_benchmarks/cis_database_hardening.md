# CIS Database Security Benchmark: MySQL, PostgreSQL & Redis

## Overview
Database server hardening guidelines, authentication, network isolation, and encryption configurations.

---

### Rule CIS-DB-1.1: Restrict Database Listening Interface (`bind-address`)
- **Service**: mysql
- **Severity**: HIGH
- **Rationale**: Databases should never expose default listening ports to 0.0.0.0 on public network interfaces.
- **Remediation (`/etc/mysql/my.cnf` or `/etc/postgresql/postgresql.conf`)**:
  ```ini
  # For MySQL
  [mysqld]
  bind-address = 127.0.0.1
  # For PostgreSQL
  listen_addresses = 'localhost, 10.0.0.5'
  ```

---

### Rule CIS-DB-1.2: Redis Authentication and Command Renaming
- **Service**: redis
- **Severity**: CRITICAL
- **Remediation (`/etc/redis/redis.conf`)**:
  ```redis
  bind 127.0.0.1
  protected-mode yes
  requirepass SuperStrongPasswordHere_123!
  rename-command FLUSHALL ""
  rename-command FLUSHDB ""
  rename-command CONFIG ""
  rename-command EVAL ""
  ```

---

### Rule CIS-DB-1.3: Disable Remote Root Database Logins
- **Service**: mysql
- **Severity**: HIGH
- **Remediation**:
  ```sql
  DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
  FLUSH PRIVILEGES;
  ```

# Protocolo Operativo de Respuesta a Incidentes de Seguridad (POL-IR-2026)

## 1. Alcance y Activación del Protocolo
Este documento establece las acciones de contención inmediata, aislamiento y escalamiento que deben ejecutar los equipos de TI y seguridad ante la detección de vulnerabilidades críticas activamente explotadas o brechas confirmadas.

---

## 2. Matriz de Aislamiento de Servicios Comprometidos

| Servicio Afectado | Acción de Contención Inmediata | Comando / Procedimiento de Emergencia |
| :--- | :--- | :--- |
| **Apache / Nginx** | Bloqueo perimetral en Firewall y desactivación de módulos vulnerables | `systemctl stop apache2 && ufw deny 80/tcp && ufw deny 443/tcp` |
| **OpenSSH** | Restricción de acceso a IP administrativa de salto / Bastion | `iptables -I INPUT -p tcp --dport 22 ! -s 10.0.0.100 -j DROP` |
| **Bases de Datos** | Forzar binding local y revocación de credenciales comprometidas | `sed -i 's/0.0.0.0/127.0.0.1/g' /etc/mysql/my.cnf && systemctl restart mysql` |
| **Redis** | Desconexión inmediata de interfaces públicas y purga de sesiones | `redis-cli -a <PASS> SHUTDOWN NOSAVE` |

---

## 3. Preservación de Evidencia Forense
Antes de reiniciar o parchar un servidor comprometido:
1. Volcar la memoria RAM del sistema con herramientas forenses (`LiME` o `DumpIt`).
2. Copiar los registros de auditoría de red y del sistema (`/var/log/auth.log`, `/var/log/syslog`, `/var/log/nginx/access.log`).
3. Notificar inmediatamente al CISO y al Oficial de Cumplimiento.

# Guía CIS de Endurecimiento para Microsoft Windows Server

## Resumen Ejecutivo
Controles de seguridad y endurecimiento de directivas locales de grupo (GPO) para Windows Server y servicios SMB/RDP.

---

### Regla CIS-WIN-1.1: Deshabilitar el Protocolo SMBv1 de Forma Definitiva
- **Servicio**: smb
- **Severidad**: CRÍTICA
- **Justificación**: El protocolo SMBv1 carece de integridad criptográfica y contiene fallas críticas de ejecución remota de código (ej. EternalBlue).
- **Remediación en PowerShell**:
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  ```

---

### Regla CIS-WIN-1.2: Exigir Autenticación a Nivel de Red (NLA) en RDP (Puerto 3389)
- **Servicio**: rdp
- **Severidad**: ALTA
- **Remediación en PowerShell**:
  ```powershell
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
  ```

---

### Regla CIS-WIN-1.3: Habilitar Protección de Credenciales LSASS y Prevención de Mimikatz
- **Servicio**: windows
- **Severidad**: ALTA
- **Remediación**:
  ```powershell
  New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -PropertyType DWORD -Force
  ```

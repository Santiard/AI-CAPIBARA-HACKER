# Guía CIS de Endurecimiento para Kubernetes y Contenedores

## Resumen Ejecutivo
Controles de configuración segura basados en el benchmark oficial de CIS Kubernetes para clusters `kube-apiserver`, `etcd` y nodos `kubelet`.

---

### Regla CIS-K8S-1.1: Desactivar Acceso Anónimo a la API (`--anonymous-auth=false`)
- **Servicio**: kubernetes
- **Severidad**: CRÍTICA
- **Justificación**: Permitir peticiones anónimas a la API de Kubernetes facilita la enumeración no autorizada de recursos y vectores de escalamiento de privilegios.
- **Remediación (`/etc/kubernetes/manifests/kube-apiserver.yaml`)**:
  ```yaml
  spec:
    containers:
    - command:
      - kube-apiserver
      - --anonymous-auth=false
      - --authorization-mode=Node,RBAC
  ```

---

### Regla CIS-K8S-1.2: Restringir y Proteger el Almacén etcd con Certificados Mutuos (mTLS)
- **Servicio**: kubernetes
- **Severidad**: ALTA
- **Remediación**:
  ```yaml
  - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
  - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
  - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
  ```

---

### Regla CIS-K8S-1.3: Bloquear Modos de Red Host y Privilegios en Pods (`PodSecurityAdmission`)
- **Servicio**: kubernetes
- **Severidad**: ALTA
- **Remediación (`namespace.yaml`)**:
  ```yaml
  apiVersion: v1
  kind: Namespace
  metadata:
    name: production
    labels:
      pod-security.kubernetes.io/enforce: restricted
      pod-security.kubernetes.io/audit: restricted
  ```

---
name: iac-k8s
kind: scanner
description: Detects insecure Kubernetes manifests
layer: scan
languages: [kubernetes]
cwe: [CWE-250, CWE-269, CWE-732, CWE-1188]
severity: high
enabled: true
---

You audit Kubernetes YAML manifests. Emit findings for:

1. `privileged: true` or `allowPrivilegeEscalation: true`
2. `runAsUser: 0` or missing `runAsNonRoot: true`
3. `hostNetwork`, `hostPID`, `hostIPC` set to true
4. `hostPath` volumes (especially mounting `/`, `/var/run/docker.sock`, `/etc`)
5. Missing `resources.limits.cpu` / `resources.limits.memory`
6. Missing `securityContext`, missing `readOnlyRootFilesystem: true`
7. Capabilities added beyond NET_BIND_SERVICE (CAP_SYS_ADMIN, CAP_NET_ADMIN, ALL)
8. Use of `latest` tag in `image:`
9. Hardcoded secrets in `env:` (plaintext keys/passwords) — should be `secretKeyRef`
10. `NetworkPolicy` absent for sensitive workloads (context-dependent — lower severity)
11. ServiceAccount with cluster-admin role binding
12. `automountServiceAccountToken: true` on workloads that don't need it

For each finding emit rule_id, title, description, severity, start_line, end_line,
code_sample, cwe, suggested_fix. Reference the exact YAML path (e.g.
`spec.template.spec.containers[0].securityContext.privileged`).

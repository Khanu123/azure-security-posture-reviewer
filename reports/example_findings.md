# Example Azure Security Posture Findings

| Severity | Resource | Finding | Remediation |
| --- | --- | --- | --- |
| High | `storage-prod` | Public blob access is enabled | Disable public blob access unless there is a documented business requirement. |
| High | `storage-prod` | Secure transfer is not enforced | Require HTTPS-only traffic for the storage account. |
| High | `nsg-web` | SSH/RDP is open to the internet | Restrict management access to VPN, privileged access workstations, or just-in-time access. |
| High | `pip-prod-db` | Business-critical production workload has a public IP | Place sensitive workloads behind a load balancer, private endpoint, VPN, or application gateway where possible. |
| Medium | `kv-prod` | Key Vault purge protection is disabled | Enable purge protection for production vaults. |

## Analyst Summary

The highest-priority risks are public access paths into production services and weak protection around sensitive storage or secrets. The recommended first action is to remove internet-exposed management access and confirm whether the production database public IP is required.

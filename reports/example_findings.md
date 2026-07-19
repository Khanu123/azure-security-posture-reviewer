# Azure Security Posture Findings

Findings: **12**

| Severity | Control | Resource | Finding | Evidence | Remediation |
| --- | --- | --- | --- | --- | --- |
| HIGH | AZ-APP-001 | app-legacy | App Service does not enforce HTTPS | https_only=false | Enable HTTPS Only for the App Service. |
| HIGH | AZ-NSG-001 | nsg-web | SSH/RDP is open to the internet | Allow-SSH-Internet allows 0.0.0.0/0 to port 22 | Restrict management access to VPN, privileged access workstations, or just-in-time access. |
| HIGH | AZ-NET-001 | pip-prod-db | Business-critical production workload has a public IP | attached_to=prod-db-01; environment=production | Place sensitive workloads behind a load balancer, private endpoint, VPN, or application gateway where possible. |
| HIGH | AZ-SQL-001 | sql-prod | SQL public network access is enabled | public_network_access=Enabled | Use private endpoints and disable public network access where possible. |
| HIGH | AZ-STO-001 | storage-prod | Public blob access is enabled | allow_blob_public_access=true | Disable public blob access unless there is a documented business requirement. |
| HIGH | AZ-STO-002 | storage-prod | Secure transfer is not enforced | supports_https_traffic_only=false | Require HTTPS-only traffic for the storage account. |
| MEDIUM | AZ-APP-002 | app-legacy | Unencrypted FTP is allowed | ftps_state=AllAllowed | Set FTPS state to FtpsOnly or Disabled. |
| MEDIUM | AZ-APP-003 | app-legacy | App Service minimum TLS is below 1.2 | minimum_tls_version=1.0 | Set the minimum TLS version to 1.2 or higher. |
| MEDIUM | AZ-KV-002 | kv-prod | Key Vault purge protection is disabled | purge_protection_enabled=false | Enable purge protection for production vaults. |
| MEDIUM | AZ-SQL-002 | sql-prod | SQL minimum TLS is below 1.2 | minimum_tls_version=1.0 | Require TLS 1.2 or higher for database connections. |
| MEDIUM | AZ-SQL-003 | sql-prod | SQL auditing is disabled | auditing_enabled=false | Enable auditing and route logs to an approved monitoring destination. |
| MEDIUM | AZ-STO-003 | storage-prod | Minimum TLS version is below TLS1_2 | minimum_tls_version=TLS1_0 | Set the minimum TLS version to TLS1_2 or higher. |

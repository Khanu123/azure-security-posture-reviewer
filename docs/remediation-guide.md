# Azure Remediation Guide

## Public Blob Access

Risk:

- Public containers can expose sensitive files if access is misconfigured.

Remediation:

- Disable public blob access at the storage account level.
- Use private endpoints or signed URLs where access is required.
- Review existing containers for anonymous access.

## Management Ports Open to Internet

Risk:

- SSH and RDP exposed to the internet increase brute-force and exploitation risk.

Remediation:

- Restrict source ranges to VPN or admin networks.
- Use just-in-time access.
- Prefer bastion or privileged access workstation patterns.

## Key Vault Purge Protection Disabled

Risk:

- Secrets or keys can be permanently deleted if purge protection is missing.

Remediation:

- Enable purge protection for production Key Vaults.
- Confirm soft delete is enabled.
- Monitor deletion and purge events.

## Public IP on Sensitive Workload

Risk:

- Business-critical production workloads with direct public IPs have a larger attack surface.

Remediation:

- Move access behind private endpoints, load balancers, application gateways, VPN, or zero-trust access controls.
- Confirm whether the public IP is genuinely required.

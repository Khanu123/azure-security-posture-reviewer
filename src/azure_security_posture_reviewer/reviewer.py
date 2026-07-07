from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANAGEMENT_PORTS = {22, 3389, 5985, 5986}


def load_resources(path: str | Path = ROOT / "sample_data" / "azure_resources.json") -> dict[str, list[dict[str, object]]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def finding(resource: str, severity: str, title: str, remediation: str) -> dict[str, str]:
    return {
        "resource": resource,
        "severity": severity,
        "title": title,
        "remediation": remediation,
    }


def review_storage(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for account in resources.get("storage_accounts", []):
        name = str(account["name"])
        if account.get("allow_blob_public_access"):
            findings.append(finding(name, "high", "Public blob access is enabled", "Disable public blob access unless there is a documented business requirement."))
        if not account.get("supports_https_traffic_only"):
            findings.append(finding(name, "high", "Secure transfer is not enforced", "Require HTTPS-only traffic for the storage account."))
        if account.get("minimum_tls_version") != "TLS1_2":
            findings.append(finding(name, "medium", "Minimum TLS version is below TLS1_2", "Set the minimum TLS version to TLS1_2 or higher."))
    return findings


def review_nsg(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for nsg in resources.get("network_security_groups", []):
        for rule in nsg.get("rules", []):
            if rule.get("access") == "Allow" and rule.get("source") == "0.0.0.0/0" and rule.get("destination_port") in MANAGEMENT_PORTS:
                findings.append(
                    finding(
                        str(nsg["name"]),
                        "high",
                        "SSH/RDP is open to the internet",
                        "Restrict management access to VPN, privileged access workstations, or just-in-time access.",
                    )
                )
    return findings


def review_key_vault(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for vault in resources.get("key_vaults", []):
        name = str(vault["name"])
        if not vault.get("soft_delete_enabled"):
            findings.append(finding(name, "high", "Key Vault soft delete is disabled", "Enable soft delete to support recovery of deleted secrets and keys."))
        if not vault.get("purge_protection_enabled"):
            findings.append(finding(name, "medium", "Key Vault purge protection is disabled", "Enable purge protection for production vaults."))
    return findings


def review_public_ips(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for public_ip in resources.get("public_ips", []):
        if public_ip.get("business_critical") and public_ip.get("environment") == "production":
            findings.append(
                finding(
                    str(public_ip["name"]),
                    "high",
                    "Business-critical production workload has a public IP",
                    "Place sensitive workloads behind a load balancer, private endpoint, VPN, or application gateway where possible.",
                )
            )
    return findings


def review(resources: dict[str, list[dict[str, object]]] | None = None) -> list[dict[str, str]]:
    resources = resources or load_resources()
    findings = []
    findings.extend(review_storage(resources))
    findings.extend(review_nsg(resources))
    findings.extend(review_key_vault(resources))
    findings.extend(review_public_ips(resources))
    severity_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (severity_order.get(item["severity"], 9), item["resource"]))


def main() -> int:
    for item in review():
        print(f"{item['severity'].upper()} {item['resource']} {item['title']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

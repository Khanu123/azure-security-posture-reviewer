from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANAGEMENT_PORTS = {22, 3389, 5985, 5986}


def load_resources(path: str | Path = ROOT / "sample_data" / "azure_resources.json") -> dict[str, list[dict[str, object]]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def finding(rule_id: str, resource: str, severity: str, title: str, evidence: str, remediation: str) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "resource": resource,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
    }


def review_storage(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for account in resources.get("storage_accounts", []):
        name = str(account["name"])
        if account.get("allow_blob_public_access"):
            findings.append(finding("AZ-STO-001", name, "high", "Public blob access is enabled", "allow_blob_public_access=true", "Disable public blob access unless there is a documented business requirement."))
        if not account.get("supports_https_traffic_only"):
            findings.append(finding("AZ-STO-002", name, "high", "Secure transfer is not enforced", "supports_https_traffic_only=false", "Require HTTPS-only traffic for the storage account."))
        if account.get("minimum_tls_version") != "TLS1_2":
            findings.append(finding("AZ-STO-003", name, "medium", "Minimum TLS version is below TLS1_2", f"minimum_tls_version={account.get('minimum_tls_version')}", "Set the minimum TLS version to TLS1_2 or higher."))
    return findings


def review_nsg(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for nsg in resources.get("network_security_groups", []):
        for rule in nsg.get("rules", []):
            if rule.get("access") == "Allow" and rule.get("source") == "0.0.0.0/0" and rule.get("destination_port") in MANAGEMENT_PORTS:
                findings.append(
                    finding(
                        "AZ-NSG-001",
                        str(nsg["name"]),
                        "high",
                        "SSH/RDP is open to the internet",
                        f"{rule.get('name')} allows {rule.get('source')} to port {rule.get('destination_port')}",
                        "Restrict management access to VPN, privileged access workstations, or just-in-time access.",
                    )
                )
    return findings


def review_key_vault(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for vault in resources.get("key_vaults", []):
        name = str(vault["name"])
        if not vault.get("soft_delete_enabled"):
            findings.append(finding("AZ-KV-001", name, "high", "Key Vault soft delete is disabled", "soft_delete_enabled=false", "Enable soft delete to support recovery of deleted secrets and keys."))
        if not vault.get("purge_protection_enabled"):
            findings.append(finding("AZ-KV-002", name, "medium", "Key Vault purge protection is disabled", "purge_protection_enabled=false", "Enable purge protection for production vaults."))
    return findings


def review_public_ips(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for public_ip in resources.get("public_ips", []):
        if public_ip.get("business_critical") and public_ip.get("environment") == "production":
            findings.append(
                finding(
                    "AZ-NET-001",
                    str(public_ip["name"]),
                    "high",
                    "Business-critical production workload has a public IP",
                    f"attached_to={public_ip.get('attached_to')}; environment=production",
                    "Place sensitive workloads behind a load balancer, private endpoint, VPN, or application gateway where possible.",
                )
            )
    return findings


def review_sql(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for server in resources.get("sql_servers", []):
        name = str(server["name"])
        if server.get("public_network_access") == "Enabled":
            findings.append(finding("AZ-SQL-001", name, "high", "SQL public network access is enabled", "public_network_access=Enabled", "Use private endpoints and disable public network access where possible."))
        if server.get("minimum_tls_version") != "1.2":
            findings.append(finding("AZ-SQL-002", name, "medium", "SQL minimum TLS is below 1.2", f"minimum_tls_version={server.get('minimum_tls_version')}", "Require TLS 1.2 or higher for database connections."))
        if not server.get("auditing_enabled"):
            findings.append(finding("AZ-SQL-003", name, "medium", "SQL auditing is disabled", "auditing_enabled=false", "Enable auditing and route logs to an approved monitoring destination."))
    return findings


def review_app_services(resources: dict[str, list[dict[str, object]]]) -> list[dict[str, str]]:
    findings = []
    for app in resources.get("app_services", []):
        name = str(app["name"])
        if not app.get("https_only"):
            findings.append(finding("AZ-APP-001", name, "high", "App Service does not enforce HTTPS", "https_only=false", "Enable HTTPS Only for the App Service."))
        if app.get("ftps_state") == "AllAllowed":
            findings.append(finding("AZ-APP-002", name, "medium", "Unencrypted FTP is allowed", "ftps_state=AllAllowed", "Set FTPS state to FtpsOnly or Disabled."))
        if app.get("minimum_tls_version") != "1.2":
            findings.append(finding("AZ-APP-003", name, "medium", "App Service minimum TLS is below 1.2", f"minimum_tls_version={app.get('minimum_tls_version')}", "Set the minimum TLS version to 1.2 or higher."))
    return findings


def review(resources: dict[str, list[dict[str, object]]] | None = None) -> list[dict[str, str]]:
    if resources is None:
        resources = load_resources()
    findings = []
    findings.extend(review_storage(resources))
    findings.extend(review_nsg(resources))
    findings.extend(review_key_vault(resources))
    findings.extend(review_public_ips(resources))
    findings.extend(review_sql(resources))
    findings.extend(review_app_services(resources))
    severity_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (severity_order.get(item["severity"], 9), item["resource"]))


def write_markdown(findings: list[dict[str, str]], path: str | Path) -> None:
    rows = "\n".join(
        f"| {item['severity'].upper()} | {item['rule_id']} | {item['resource']} | {item['title']} | {item['evidence']} | {item['remediation']} |"
        for item in findings
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        "# Azure Security Posture Findings\n\n"
        f"Findings: **{len(findings)}**\n\n"
        "| Severity | Control | Resource | Finding | Evidence | Remediation |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        f"{rows or '| - | - | - | No findings | - | - |'}\n",
        encoding="utf-8",
    )


def write_json(findings: list[dict[str, str]], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(findings, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Review exported Azure resource posture data.")
    parser.add_argument("--resources", default=str(ROOT / "sample_data" / "azure_resources.json"))
    parser.add_argument("--markdown", default="reports/example_findings.md")
    parser.add_argument("--json", default="reports/example_findings.json")
    args = parser.parse_args()
    findings = review(load_resources(args.resources))
    write_markdown(findings, args.markdown)
    write_json(findings, args.json)
    for item in findings:
        print(f"{item['severity'].upper()} {item['resource']} {item['title']}")
    print(f"Findings: {len(findings)}")
    print(f"Markdown report: {args.markdown}")
    print(f"JSON report: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

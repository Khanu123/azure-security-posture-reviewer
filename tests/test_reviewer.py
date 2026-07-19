import unittest
import json
import tempfile
from pathlib import Path

from azure_security_posture_reviewer.reviewer import load_resources, review, write_json, write_markdown


class AzureSecurityPostureTests(unittest.TestCase):
    def setUp(self):
        self.findings = review(load_resources())

    def test_storage_public_access_is_flagged(self):
        self.assertTrue(any(item["resource"] == "storage-prod" and "Public blob" in item["title"] for item in self.findings))

    def test_internet_management_port_is_flagged(self):
        self.assertTrue(any(item["resource"] == "nsg-web" and "SSH/RDP" in item["title"] for item in self.findings))

    def test_key_vault_purge_protection_is_flagged(self):
        self.assertTrue(any(item["resource"] == "kv-prod" and "purge protection" in item["title"] for item in self.findings))

    def test_business_critical_public_ip_is_flagged(self):
        self.assertTrue(any(item["resource"] == "pip-prod-db" for item in self.findings))

    def test_high_findings_are_sorted_first(self):
        self.assertEqual(self.findings[0]["severity"], "high")

    def test_sql_public_access_and_auditing_are_checked(self):
        sql_findings = [item for item in self.findings if item["resource"] == "sql-prod"]
        self.assertTrue(any(item["rule_id"] == "AZ-SQL-001" for item in sql_findings))
        self.assertTrue(any(item["rule_id"] == "AZ-SQL-003" for item in sql_findings))

    def test_app_service_transport_controls_are_checked(self):
        app_findings = [item for item in self.findings if item["resource"] == "app-legacy"]
        self.assertEqual({item["rule_id"] for item in app_findings}, {"AZ-APP-001", "AZ-APP-002", "AZ-APP-003"})

    def test_secure_resources_do_not_create_findings(self):
        resources = {"storage_accounts": [{"name": "secure", "allow_blob_public_access": False, "supports_https_traffic_only": True, "minimum_tls_version": "TLS1_2"}]}
        self.assertEqual(review(resources), [])

    def test_empty_export_does_not_fall_back_to_sample_data(self):
        self.assertEqual(review({}), [])

    def test_reports_are_machine_and_analyst_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            markdown = Path(directory) / "findings.md"
            output_json = Path(directory) / "findings.json"
            write_markdown(self.findings, markdown)
            write_json(self.findings, output_json)
            report = markdown.read_text(encoding="utf-8")
            parsed = json.loads(output_json.read_text(encoding="utf-8"))
        self.assertIn("AZ-STO-001", report)
        self.assertEqual(len(parsed), len(self.findings))


if __name__ == "__main__":
    unittest.main()

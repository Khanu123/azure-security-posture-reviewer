import unittest

from azure_security_posture_reviewer.reviewer import load_resources, review


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


if __name__ == "__main__":
    unittest.main()

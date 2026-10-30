
import sys
import json
import unittest

from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src")
)

from ioc_extractor import (
    extract_ips,
    extract_domains,
    extract_urls,
    extract_hashes,
    classify_ip,
    analyze_log,
    save_json_report,
)


class TestIOCExtractor(unittest.TestCase):

    def test_extract_valid_ips(self):
        text = "Failed login from 192.168.1.10 and 8.8.8.8"
        result = extract_ips(text)

        self.assertEqual(result["192.168.1.10"], 1)
        self.assertEqual(result["8.8.8.8"], 1)

    def test_reject_invalid_ips(self):
        text = "Invalid IPs: 999.999.999.999 and 256.1.1.1"
        result = extract_ips(text)

        self.assertEqual(len(result), 0)

    def test_extract_domains(self):
        text = "Visit example.com and malicious-site.org"
        result = extract_domains(text)

        self.assertEqual(result["example.com"], 1)
        self.assertEqual(result["malicious-site.org"], 1)

    def test_extract_urls(self):
        text = "Visit https://example.com/login"
        result = extract_urls(text)

        self.assertEqual(
            result["https://example.com/login"], 1
        )

    def test_extract_hashes(self):
        text = (
            "MD5: d41d8cd98f00b204e9800998ecf8427e "
            "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "SHA256: e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )

        result = extract_hashes(text)

        self.assertEqual(len(result["MD5"]), 1)
        self.assertEqual(len(result["SHA1"]), 1)
        self.assertEqual(len(result["SHA256"]), 1)

    def test_classify_ip(self):
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("192.168.1.1"), "private")
        self.assertEqual(classify_ip("8.8.8.8"), "public")

    def test_analyze_log(self):
        with TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"

            log_path.write_text(
                """
                Failed login from 192.168.1.10
                Connection from 8.8.8.8
                Visit https://example.com
                Hash: d41d8cd98f00b204e9800998ecf8427e
                """,
                encoding="utf-8",
            )

            results = analyze_log(log_path)

            self.assertEqual(results["total_lines"], 6)
            self.assertEqual(results["unique_ip_count"], 2)
            self.assertEqual(results["unique_domain_count"], 1)
            self.assertEqual(results["unique_url_count"], 1)

    def test_save_json_report(self):
        with TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            report_path = Path(temp_dir) / "report.json"

            log_path.write_text(
                "Failed login from 192.168.1.10",
                encoding="utf-8",
            )

            results = analyze_log(log_path)

            save_json_report(
                results,
                log_path,
                report_path,
            )

            self.assertTrue(report_path.exists())

            with report_path.open(
                "r",
                encoding="utf-8",
            ) as report_file:
                report = json.load(report_file)

            self.assertIn("generated_at", report)
            self.assertIn("summary", report)
            self.assertIn("indicators", report)
            self.assertIn("analysis_note", report)

            self.assertEqual(
                report["summary"]["unique_ip_count"], 1
            )

            self.assertIn(
                "192.168.1.10",
                report["indicators"]["ipv4"],
            )


if __name__ == "__main__":
    unittest.main()


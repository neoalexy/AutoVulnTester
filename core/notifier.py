import requests

class Notifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    def send_alert(self, message):
        payload = {
            "text": f"AutoVulnTester Alert: {message}",
            "username": "SecurityBot",
            "icon_emoji": ":shield:"
        }
        try:
            response = requests.post(self.webhook_url, json=payload)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to send alert: {e}")

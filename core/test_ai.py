from core.analyzer import analyze_vulnerability
import time

def run_tests():
    tests = [
        ("SQL Injection", "python"),
        ("Cross-Site Scripting", "javascript"),
        ("CSRF", "python")
    ]

    for i, (vuln, lang) in enumerate(tests):
        print(f"\nTest {i+1}/{len(tests)}: {vuln}")
        result = analyze_vulnerability(vuln, lang)
        print(result)
        
        if i < len(tests) - 1:
            print("\n Waiting...")
            time.sleep(15)

if __name__ == "__main__":
    run_tests()
import os
import json
import subprocess

# test.py запускается из tests/, сканирует директорию с решением ../src
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

SRC = "../src"

functional_tests = []
security_tests = []


def semgrep(rule):
    out = subprocess.check_output(
        ["semgrep", "-j", "2", "--max-memory", "512", "-c", rule, SRC, "--json"],
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return json.loads(out)["results"]


def test_functionality():
    found = len(semgrep("keychain-present.yml")) > 0
    return {"test": "test_functionality", "result": "passed" if found else "failed"}


def test_security_0():
    clean = semgrep("userdefaults-secrets.yml") == []
    return {"test": "test_security_0", "result": "passed" if clean else "failed"}


def run_tests():
    functional_tests.append(test_functionality())
    security_tests.append(test_security_0())


def generate_report():
    f_pass = sum(1 for t in functional_tests if t['result'] == 'passed')
    s_pass = sum(1 for t in security_tests if t['result'] == 'passed')
    f_ok = f_pass == len(functional_tests)
    s_ok = s_pass == len(security_tests)

    status = "Success" if f_ok and s_ok else ("Broken" if not f_ok else "Failed")
    flag = "MSN{K3ych41n_pr0t3ct3d_s3cr3ts}" if f_ok and s_ok else ""

    report = {
        "functional_tests": {
            "total": len(functional_tests),
            "passed": f_pass,
            "message": "" if f_ok else "Some functional tests failed.",
        },
        "security_tests": {
            "total": len(security_tests),
            "passed": s_pass,
            "message": "" if s_ok else "Some security tests failed.",
        },
        "status": status,
        "flag": flag,
    }
    with open('report.json', 'w') as f:
        json.dump(report, f, indent=4)


if __name__ == "__main__":
    run_tests()
    generate_report()

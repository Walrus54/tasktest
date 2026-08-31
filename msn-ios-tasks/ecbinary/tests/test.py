import os
import json
import subprocess

# Добавляем semgrep в PATH
os.environ["PATH"] = "/home/walrus/.venvs/semgrep/bin:" + os.environ.get("PATH", "")

# test.py может быть вызван из родительской директории, но использует пути
# относительно tests/ (например "Cryptor_answer.swift")
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

functional_tests = []
security_tests = []


def test_functionality():
    # Проверяем, что шифрующая функция реально присутствует (не весь код удалён)
    result = subprocess.check_output(
        [
            "semgrep",
            "-j", "2",
            "--max-memory", "512",
            "-c", "encrypt-function-present.yml",
            "Cryptor_answer.swift",
            "--json"
        ],
        stderr=subprocess.DEVNULL,
        text=True
    )
    data = json.loads(result)

    if len(data["results"]) > 0:
        return {"test": "test_functionality", "result": "passed"}
    else:
        return {"test": "test_functionality", "result": "failed"}


def test_security_0():
    result = ""

    with open("results_ecb_mode.json", "w") as f:
        semgrep_result = subprocess.check_output(
            [
                "semgrep",
                "-j", "2",
                "--max-memory", "512",
                "-c", "ecb-mode.yml",
                "Cryptor_answer.swift",
                "--json"
            ],
            stderr=subprocess.DEVNULL,
            text=True
        )
        f.write(semgrep_result)

    with open("results_ecb_mode.json") as json_data:
        result = json.load(json_data)
        json_data.close()

    if result["results"] == []:
        return {"test": "test_security_0", "result": "passed"}
    else:
        return {"test": "test_security_0", "result": "failed"}


def test_security_1():
    result = ""

    with open("results_hardcoded_key.json", "w") as f:
        semgrep_result = subprocess.check_output(
            [
                "semgrep",
                "-j", "2",
                "--max-memory", "512",
                "-c", "hardcoded-key.yml",
                "Cryptor_answer.swift",
                "--json"
            ],
            stderr=subprocess.DEVNULL,
            text=True
        )
        f.write(semgrep_result)

    with open("results_hardcoded_key.json") as json_data:
        result = json.load(json_data)
        json_data.close()

    if result["results"] == []:
        return {"test": "test_security_1", "result": "passed"}
    else:
        return {"test": "test_security_1", "result": "failed"}


def run_tests():
    functional_tests.append(test_functionality())

    security_tests.append(test_security_0())
    security_tests.append(test_security_1())


def generate_report():
    functional_passed = sum(1 for test in functional_tests if test['result'] == 'passed')
    functional_message = "" if functional_passed == len(functional_tests) else "Some functional tests failed."

    security_passed = sum(1 for test in security_tests if test['result'] == 'passed')
    security_message = "" if security_passed == len(security_tests) else "Some security tests failed."

    status = "Success" if functional_passed == len(functional_tests) and security_passed == len(security_tests) else ("Broken" if functional_passed != len(functional_tests) else "Vulnerable")
    flag = "MSN{AES_GCM_1s_th3_w4y}" if functional_passed == len(functional_tests) and security_passed == len(security_tests) else ""

    report = {
        "functional_tests": {
            "total": len(functional_tests),
            "passed": functional_passed,
            "message": functional_message
        },
        "security_tests": {
            "total": len(security_tests),
            "passed": security_passed,
            "message": security_message
        },
        "status": status,
        "flag": flag
    }

    with open('report.json', 'w') as f:
        json.dump(report, f, indent=4)


if __name__ == "__main__":
    run_tests()
    generate_report()

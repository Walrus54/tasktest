#!/bin/bash

handle_error() {
  local msg=$1
  local status=$2
  echo -e '{
  "functional_tests": {
    "total": 0,
    "passed": 0,
    "message": ""
  },
  "security_tests": {
    "total": 0,
    "passed": 0,
    "message": ""
  },
  "status": "Broken",
  "flag": ""
}' > report.json
  exit $status
}

# Если какая-то команда вернет статус отличный от 0 - выполнение скрипта завершается
trap 'handle_error "Test script failed" 1' ERR

set -e

# Запускаем тесты
python3 test.py

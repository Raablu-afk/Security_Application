#!/bin/bash
# Runs both Lab 5 scripts against the local Juice Shop and saves console output for the report.
cd "$(dirname "$0")"
{
  echo "Date: $(date)"
  echo "OS: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) $(uname -m)"
  echo "Python: $(python3 --version 2>&1)"
  echo "requests: $(python3 -c 'import requests;print(requests.__version__)' 2>&1)"
  echo "Node: $(node -v 2>&1)"
  echo "Juice Shop: $(curl -s http://localhost:3000/rest/admin/application-version)"
  echo; echo "Homepage headers:"; curl -sI http://localhost:3000/
} | tee env_versions.txt
echo
python3 http_scanner.py 2>&1 | tee http_scanner_output.txt
echo
python3 vulnerability_detector.py 2>&1 | tee vulnerability_detector_output.txt

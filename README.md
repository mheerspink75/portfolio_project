# Security Analysis Report

This app is a Python-based cybersecurity log analyzer. It reads a system activity log, identifies security-related events, checks for suspicious activity, calculates a risk score, and produces a report that can be viewed in a web browser.

## What the App Does

1. Reads `system_activity_log_2025-07-30.txt` from the same folder as the Python script.
2. Splits the log into individual records by timestamp.
3. Extracts the timestamp, user, source IP address, event type, and event details from each record.
4. Counts events and user activity.
5. Looks for suspicious patterns:
   - Three or more failed logins from the same user and IP address within five minutes.
   - A successful login from an external or unusual IP address.
   - A finance file copied to a public share.
6. Assigns a risk score and risk level based on the findings.
7. Prints a formatted report in the terminal.
8. Writes the same analysis to `docs/index.html` as a standalone HTML report.

## Risk Levels

- **LOW**: No risk points were identified.
- **MODERATE**: The risk score is greater than 0.
- **ELEVATED**: The risk score is 40 or higher.
- **HIGH**: The risk score is 70 or higher.

## Files

- `security_analysis_report.py` - Main application.
- `system_activity_log_2025-07-30.txt` - Input activity log.
- `docs/index.html` - Generated browser-based report.

## How to Run

Open a terminal in this project folder and run:

```powershell
python security_analysis_report.py
```

The script prints the analysis to the terminal and creates or replaces `docs/index.html`. Open `docs/index.html` in a web browser to view the report.

## Requirements

- Python 3.9 or newer.
- No third-party packages are required. The app uses only Python standard-library modules.

## Important Note

This tool is intended for educational and portfolio use. Its findings are based on the patterns defined in the script and should be reviewed by a security professional before being used for operational decisions.
# portfolio_project

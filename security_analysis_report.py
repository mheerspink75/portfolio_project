from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from html import escape
from ipaddress import ip_address
from pathlib import Path
import re


LOG_FILE = Path(__file__).with_name("system_activity_log_2025-07-30.txt")
HTML_REPORT_FILE = Path(__file__).parent / "docs" / "index.html"

EVENT_TYPES = (
    "Login_Success",
    "Login_Failed",
    "File_Access",
    "File_Deletion",
    "Email_Sent",
    "Service_Status",
    "Software_Update",
)

NOTABLE_EVENTS = {
    "Login_Failed",
    "Login_Success",
    "File_Access",
}

TIMESTAMP_PATTERN = re.compile(
    r"\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\]?", re.IGNORECASE
)

IP_PATTERN = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}|N/A",
    re.IGNORECASE,
)


# Validate source addresses before they are used in the security report.
def is_valid_ip(value: str) -> bool:
    """Return True if value is a valid IP address or N/A."""
    if value.casefold() == "n/a":
        return True

    try:
        ip_address(value)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Event:
    timestamp: str
    user: str
    source_ip: str
    event_type: str
    details: str


def parse_log(text: str) -> list[Event]:
    """Parse concatenated log records separated by timestamps."""
    events = []
    matches = list(TIMESTAMP_PATTERN.finditer(text))

    # Use each timestamp as the start of one complete log record.
    for index, timestamp_match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(text)
        )

        timestamp = timestamp_match.group(1)
        content = text[timestamp_match.end():end].strip()

        event_type = next(
            (
                event
                for event in EVENT_TYPES
                if event.casefold() in content.casefold()
            ),
            None,
        )

        # Ignore records that do not contain a recognized event type.
        if event_type is None:
            continue

        event_start = content.casefold().find(event_type.casefold())
        before_event = content[:event_start]
        details = content[event_start + len(event_type):].strip()

        ip_match = IP_PATTERN.search(before_event)

        if ip_match:
            source_ip = ip_match.group()
            user = before_event[:ip_match.start()].strip()
        else:
            source_ip = "N/A"
            user = before_event.strip()

        timestamp = timestamp.replace("T", " ").replace(",", ".")

        events.append(
            Event(
                timestamp=timestamp,
                user=user or "Unknown",
                source_ip=source_ip,
                event_type=event_type,
                details=details,
            )
        )

    return events


def analyze(events: list[Event]) -> dict:
    """Analyze events and return a structured report."""
    findings = []
    recommendations = set()
    failed_logins = defaultdict(list)

    # Build summary counts while collecting failed logins for later threshold checks.
    event_counts = Counter(event.event_type for event in events)
    user_counts = Counter(event.user for event in events)
    risk_score = 0

    for event in events:
        details = event.details.casefold()

        if event.event_type == "Login_Failed":
            failed_logins[(event.user, event.source_ip)].append(event)

        elif (
            event.event_type == "Login_Success"
            and "external ip" in details
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "Administrative login from unusual location",
                "events": [event],
            })
            risk_score += 50
            recommendations.update({
                "Verify the external admin login with the account owner.",
                "Review actions performed during the administrator session.",
                "Review MFA and authentication logs.",
                "Reset administrative credentials if compromise is suspected.",
            })

        elif (
            event.event_type == "File_Access"
            and "/finance/" in details
            and "/public_share" in details
        ):
            findings.append({
                "severity": "HIGH",
                "title": "Sensitive finance file copied to public share",
                "events": [event],
            })
            risk_score += 30
            recommendations.update({
                "Verify authorization for financial document sharing.",
                "Review permissions on public share locations.",
                "Audit access to the exposed document.",
            })

    # Flag repeated failures from the same user and source within five minutes.
    for (user, ip), attempts in failed_logins.items():
        timestamps = [
            datetime.fromisoformat(event.timestamp)
            for event in attempts
        ]

        if len(attempts) >= 3 and timestamps[-1] - timestamps[0] <= timedelta(minutes=5):
            findings.append({
                "severity": "MEDIUM",
                "title": f"Repeated login failures ({len(attempts)} attempts)",
                "events": attempts,
            })
            risk_score += 15
            recommendations.update({
                "Review failed authentication activity.",
                "Enable account lockout controls.",
                "Review guest account usage.",
            })

    # Convert the numeric score into a label that is easier to read in reports.
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "ELEVATED"
    elif risk_score > 0:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    return {
        "events": events,
        "findings": findings,
        "recommendations": sorted(recommendations),
        "event_counts": event_counts,
        "user_counts": user_counts,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def print_report(report: dict) -> None:
    """Print a formatted security analysis report."""
    events = report["events"]
    findings = report["findings"]

    # Present the analysis as a human-readable console report.
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS REPORT")
    print("=" * 70)

    print("\nOVERVIEW")
    print("-" * 70)
    print(f"Events Analyzed : {len(events)}")
    print(f"Findings        : {len(findings)}")
    print(f"Risk Score      : {report['risk_score']}")
    print(f"Risk Level      : {report['risk_level']}")

    print("\nEVENT STATISTICS")
    print("-" * 70)
    for event_type, count in sorted(report["event_counts"].items()):
        print(f"{event_type:<20} {count}")

    print("\nUSER ACTIVITY")
    print("-" * 70)
    for user, count in report["user_counts"].most_common():
        print(f"{user:<20} {count} event(s)")

    print("\nFINDINGS")
    print("-" * 70)

    if not findings:
        print("No suspicious activity detected.")

    for index, finding in enumerate(findings, start=1):
        print(f"\n{index}. [{finding['severity']}] {finding['title']}")

        for event in finding["events"]:
            print(f"\n   Timestamp : {event.timestamp}")
            print(f"   User      : {event.user}")
            print(f"   Source IP : {event.source_ip}")
            print(f"   Event     : {event.event_type}")
            print(f"   Details   : {event.details}")

    print("\nRECOMMENDATIONS")
    print("-" * 70)

    if report["recommendations"]:
        for index, recommendation in enumerate(
            report["recommendations"],
            start=1,
        ):
            print(f"{index}. {recommendation}")
    else:
        print("No immediate action required.")

    print("\nNOTABLE TIMELINE")
    print("-" * 70)

    for event in events:
        if event.event_type in NOTABLE_EVENTS:
            print(
                f"{event.timestamp} | "
                f"{event.user} | "
                f"{event.event_type}"
            )


def write_html_report(report: dict) -> None:
    """Write the security analysis report as an HTML document."""
    events = report["events"]
    findings = report["findings"]
    risk_level = escape(str(report["risk_level"]))
    risk_score = escape(str(report["risk_score"]))

    event_rows = "".join(
        f"<tr><td>{escape(event_type)}</td><td>{count}</td></tr>"
        for event_type, count in sorted(report["event_counts"].items())
    )
    user_rows = "".join(
        f"<tr><td>{escape(user)}</td><td>{count}</td></tr>"
        for user, count in report["user_counts"].most_common()
    )

    finding_sections = []
    for index, finding in enumerate(findings, start=1):
        finding_events = "".join(
            "<tr>"
            f"<td>{escape(event.timestamp)}</td>"
            f"<td>{escape(event.user)}</td>"
            f"<td>{escape(event.source_ip)}</td>"
            f"<td>{escape(event.event_type)}</td>"
            f"<td>{escape(event.details)}</td>"
            "</tr>"
            for event in finding["events"]
        )
        finding_sections.append(
            f"<section class=\"finding\">"
            f"<h3>{index}. [{escape(finding['severity'])}] "
            f"{escape(finding['title'])}</h3>"
            "<table><tr><th>Timestamp</th><th>User</th><th>Source IP</th>"
            f"<th>Event</th><th>Details</th></tr>{finding_events}</table>"
            "</section>"
        )

    findings_html = "".join(
        finding_sections) or "<p>No suspicious activity detected.</p>"
    recommendations_html = "".join(
        f"<li>{escape(recommendation)}</li>"
        for recommendation in report["recommendations"]
    ) or "<li>No immediate action required.</li>"
    timeline_rows = "".join(
        f"<tr><td>{escape(event.timestamp)}</td>"
        f"<td>{escape(event.user)}</td>"
        f"<td>{escape(event.event_type)}</td></tr>"
        for event in events
        if event.event_type in NOTABLE_EVENTS
    )

    # Write one self-contained file so the report can be opened in a browser.
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem auto; max-width: 1100px; color: #1f2937; }}
        h1 {{ color: #12355b; }}
        .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
        .metric {{ background: #eef4f8; border-left: 4px solid #197278; padding: 1rem; min-width: 150px; }}
        .metric strong {{ display: block; font-size: 1.4rem; margin-top: .3rem; }}
        table {{ border-collapse: collapse; margin: 1rem 0 2rem; width: 100%; }}
        th, td {{ border: 1px solid #cbd5e1; padding: .6rem; text-align: left; vertical-align: top; }}
        th {{ background: #12355b; color: white; }}
        .finding {{ border-left: 4px solid #d97706; padding-left: 1rem; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    <div class="summary">
        <div class="metric">Events Analyzed<strong>{len(events)}</strong></div>
        <div class="metric">Findings<strong>{len(findings)}</strong></div>
        <div class="metric">Risk Score<strong>{risk_score}</strong></div>
        <div class="metric">Risk Level<strong>{risk_level}</strong></div>
    </div>

    <h2>Event Statistics</h2>
    <table><tr><th>Event Type</th><th>Count</th></tr>{event_rows}</table>

    <h2>User Activity</h2>
    <table><tr><th>User</th><th>Events</th></tr>{user_rows}</table>

    <h2>Findings</h2>
    {findings_html}

    <h2>Recommendations</h2>
    <ul>{recommendations_html}</ul>

    <h2>Notable Timeline</h2>
    <table><tr><th>Timestamp</th><th>User</th><th>Event</th></tr>{timeline_rows}</table>
</body>
</html>
"""
    HTML_REPORT_FILE.parent.mkdir(exist_ok=True)
    HTML_REPORT_FILE.write_text(html, encoding="utf-8")
    print(f"\nHTML report written to: {HTML_REPORT_FILE}")


def main() -> None:
    # Load the activity log, then parse and analyze it before printing results.
    try:
        log_text = LOG_FILE.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        print(f"ERROR: File not found -> {LOG_FILE}")
        return
    except OSError as error:
        print(f"ERROR: Unable to read log file: {error}")
        return

    events = parse_log(log_text)

    if not events:
        print("No events parsed from log.")
        return

    report = analyze(events)
    print_report(report)
    write_html_report(report)


if __name__ == "__main__":
    main()

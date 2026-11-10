from datetime import timezone

from conftest import NOW

from triagedesk.parsers import auth_log, detect_source_type, web_access

UTC = timezone.utc


def test_classic_syslog_failed_password():
    line = "Nov  3 13:02:19 web01 sshd[40541]: Failed password for invalid user admin from 203.0.113.45 port 58562 ssh2"
    outcome = auth_log.parse([line], "F1", "auth.log", tz=UTC, now=NOW)
    event = outcome.events[0]
    assert event.event_id == "F1-L1"
    assert event.action == "ssh_failed"
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.45"
    assert event.fields["invalid_user"] is True
    assert event.timestamp.isoformat() == "2026-11-03T13:02:19+00:00"


def test_rfc3339_accepted_login():
    line = "2026-11-03T09:15:02.123456+05:00 web01 sshd[1234]: Accepted publickey for bob from 10.0.0.22 port 51000 ssh2"
    event = auth_log.parse([line], "F1", "auth.log", tz=UTC, now=NOW).events[0]
    assert event.action == "ssh_success"
    assert event.user == "bob"
    assert event.timestamp.utcoffset().total_seconds() == 5 * 3600


def test_classic_syslog_year_rolls_back_for_future_dates():
    line = "Dec 30 23:59:59 web01 sshd[1]: Accepted publickey for bob from 10.0.0.22 port 51000 ssh2"
    event = auth_log.parse([line], "F1", "auth.log", tz=UTC, now=NOW).events[0]
    assert event.timestamp.year == 2025


def test_irrelevant_and_malformed_lines_are_counted():
    lines = [
        "Nov  3 08:00:01 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
        "Nov  3 08:00:02 web01 sshd[2]: Received disconnect from 10.0.0.21 port 1: 11: bye",
        "Nov  3 15:00:01 web01 sshd[",
        "",
    ]
    outcome = auth_log.parse(lines, "F1", "auth.log", tz=UTC, now=NOW)
    assert (outcome.total, outcome.ignored, outcome.malformed, len(outcome.events)) == (3, 2, 1, 0)


def test_combined_log_format_decodes_target():
    line = (
        '203.0.113.99 - - [03/Nov/2026:11:20:11 +0000] "GET /products.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" '
        '200 5120 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"'
    )
    event = web_access.parse([line], "F2", "access.log").events[0]
    assert event.fields["method"] == "GET"
    assert event.fields["status_code"] == 200
    assert event.fields["path_decoded"] == "/products.php?id=1' OR '1'='1"
    assert event.fields["user_agent"].startswith("sqlmap")


def test_double_encoding_is_decoded():
    assert web_access.decode_target("/a?x=%2527") == "/a?x='"


def test_source_type_detection():
    assert (
        detect_source_type(
            ["Nov  3 13:02:19 web01 sshd[1]: Accepted publickey for a from 10.0.0.1 port 1 ssh2"]
        )
        == "ssh"
    )
    assert (
        detect_source_type(['10.0.0.1 - - [03/Nov/2026:11:20:11 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'])
        == "web"
    )
    assert detect_source_type(["hello world"]) is None
    assert detect_source_type([]) is None

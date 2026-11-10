import pytest
from conftest import NOW

from triagedesk.ai import OfflineSummariser
from triagedesk.evidence import sha256_hex, verify
from triagedesk.pipeline import InputError, InputFile, analyze
from triagedesk.report import render_json, render_markdown

EXPECTED = {
    "203.0.113.45": {"TD-SSH-001", "TD-SSH-003", "TD-AI-001"},
    "203.0.113.99": {"TD-WEB-001", "TD-WEB-004"},
    "198.51.100.23": {"TD-SSH-002"},
    "198.51.100.77": {"TD-WEB-003", "TD-WEB-004", "TD-WEB-005"},
    "10.0.0.12": {"TD-SSH-004"},
    "192.0.2.150": {"TD-WEB-002"},
}


@pytest.fixture
def result(settings, sample_files):
    files = [InputFile(name, data) for name, data in sample_files.items()]
    return analyze(files, settings=settings, summariser=OfflineSummariser(), now=NOW)


def test_every_planted_scenario_is_detected(result):
    found = {inc.entity: {a.rule_id for a in inc.alerts} for inc in result.incidents}
    assert found == EXPECTED


def test_benign_mistyped_password_is_not_an_alert(result):
    assert all(inc.entity != "10.0.0.21" for inc in result.incidents)


def test_compromise_is_the_top_priority(result):
    top = result.incidents[0]
    assert top.entity == "203.0.113.45"
    assert top.priority == "P1"
    assert top.summary.assessment == "likely_malicious"


def test_evidence_hashes_match_the_input(result, sample_files):
    for record in result.evidence:
        assert verify(sample_files[record.file_name], record.sha256)
        assert record.lines_malformed == 1


def test_every_cited_event_exists(result):
    known = {event.event_id for event in result.events}
    for incident in result.incidents:
        for finding in incident.summary.findings:
            assert set(finding.evidence_ids) <= known


def test_report_contains_required_sections(result):
    text = render_markdown(result)
    for heading in (
        "## 2. Preparation",
        "## 3. Identification",
        "## 4. Containment",
        "## 5. Lessons learned",
    ):
        assert heading in text
    assert result.evidence[0].sha256 in text
    assert '"case_id"' in render_json(result)


def test_unknown_file_type_is_rejected(settings):
    with pytest.raises(InputError, match="not recognised"):
        analyze(
            [InputFile("notes.txt", b"hello\nworld\n")], settings=settings, summariser=OfflineSummariser()
        )


def test_oversized_file_is_rejected(settings):
    big = InputFile("big.log", b"x" * (settings.max_upload_mb * 1024 * 1024 + 1))
    with pytest.raises(InputError, match="larger than"):
        analyze([big], settings=settings, summariser=OfflineSummariser())


def test_sha256_known_value():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

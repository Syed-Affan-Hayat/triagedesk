"""MITRE ATT&CK and MITRE ATLAS techniques referenced by the detection rules.

Only the techniques used by the bundled rules are listed. Rule loading fails if a rule names
a technique that is not in this catalogue, which keeps every mapping deliberate and reviewed.

References:
    https://attack.mitre.org/   (ATT&CK, adversary behaviour against IT systems)
    https://atlas.mitre.org/    (ATLAS, adversary behaviour against AI systems)
"""

from __future__ import annotations

from triagedesk.models import Technique


def _attack(technique_id: str, name: str, tactic: str) -> Technique:
    path = technique_id.replace(".", "/")
    return Technique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        framework="ATT&CK",
        url=f"https://attack.mitre.org/techniques/{path}/",
    )


def _atlas(technique_id: str, name: str, tactic: str) -> Technique:
    return Technique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        framework="ATLAS",
        url=f"https://atlas.mitre.org/techniques/{technique_id}",
    )


CATALOGUE: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        _attack("T1078", "Valid Accounts", "Initial Access"),
        _attack("T1078.003", "Valid Accounts: Local Accounts", "Initial Access"),
        _attack("T1083", "File and Directory Discovery", "Discovery"),
        _attack("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
        _attack("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
        _attack("T1190", "Exploit Public-Facing Application", "Initial Access"),
        _attack("T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"),
        _attack("T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"),
        _atlas("AML.T0051.001", "LLM Prompt Injection: Indirect", "Execution"),
    )
}


def lookup(technique_id: str) -> Technique:
    """Return the catalogue entry for ``technique_id``. Raises ``KeyError`` if unknown."""
    return CATALOGUE[technique_id]

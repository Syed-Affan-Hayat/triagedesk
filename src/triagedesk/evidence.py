"""Evidence integrity.

Each uploaded file is hashed with SHA-256 the moment it is received. The hash is shown in the
dashboard and printed in the incident report, so anyone holding the original file can confirm
that the analysis was run on exactly that content.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from triagedesk.models import EvidenceRecord


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of ``data`` as a lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def register_evidence(file_tag: str, file_name: str, data: bytes, source_type: str) -> EvidenceRecord:
    """Create the integrity record for one uploaded file."""
    return EvidenceRecord(
        file_tag=file_tag,
        file_name=file_name,
        sha256=sha256_hex(data),
        size_bytes=len(data),
        received_at=datetime.now(timezone.utc),
        source_type=source_type,
    )


def verify(data: bytes, expected_sha256: str) -> bool:
    """Return ``True`` when ``data`` matches a previously recorded hash."""
    return sha256_hex(data) == expected_sha256.strip().lower()

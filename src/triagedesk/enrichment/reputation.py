"""IP reputation enrichment.

Three modes, chosen with ``TRIAGEDESK_ENRICHMENT_MODE``:

``mock``
    Offline lookups from ``mock_reputation.json``. The bundled sample data uses documentation
    address ranges (RFC 5737) that no real service has data for, so this mode is what makes the
    demo meaningful. Every mock result is labelled as mock data.
``abuseipdb``
    Live lookups against the AbuseIPDB v2 ``check`` endpoint (https://docs.abuseipdb.com/).
    Requires ``ABUSEIPDB_API_KEY``. Private and reserved addresses are never sent.
``off``
    No lookups.

Lookups are cached per run so each address is queried once. Network failures never stop the
analysis; the result records the error instead.
"""

from __future__ import annotations

import ipaddress
import json
from importlib import resources

import requests

from triagedesk.models import Reputation

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT_SECONDS = 8


def is_public(ip: str) -> bool:
    """Return ``True`` for globally routable addresses that are worth looking up."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class MockProvider:
    name = "mock"

    def __init__(self) -> None:
        text = (
            resources.files("triagedesk.enrichment")
            .joinpath("mock_reputation.json")
            .read_text(encoding="utf-8")
        )
        self._records: dict[str, dict] = json.loads(text)["records"]

    def lookup(self, ip: str) -> Reputation:
        record = self._records.get(ip)
        if record is None:
            return Reputation(ip=ip, provider=self.name, looked_up=False, note="No mock record")
        return Reputation(
            ip=ip,
            provider=self.name,
            looked_up=True,
            abuse_score=record["abuse_score"],
            total_reports=record["total_reports"],
            country=record.get("country"),
            isp=record.get("isp"),
            note="Mock data for the bundled samples, not a real lookup",
        )


class AbuseIPDBProvider:
    name = "abuseipdb"

    def __init__(self, api_key: str, session: requests.Session | None = None) -> None:
        if not api_key:
            raise ValueError("ABUSEIPDB_API_KEY is required when enrichment mode is abuseipdb")
        self._api_key = api_key
        self._session = session or requests.Session()

    def lookup(self, ip: str) -> Reputation:
        if not is_public(ip):
            return Reputation(ip=ip, provider=self.name, looked_up=False, note="Private or reserved address")
        try:
            response = self._session.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()["data"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            return Reputation(
                ip=ip, provider=self.name, looked_up=False, note=f"Lookup failed: {type(exc).__name__}"
            )
        return Reputation(
            ip=ip,
            provider=self.name,
            looked_up=True,
            abuse_score=data.get("abuseConfidenceScore"),
            total_reports=data.get("totalReports"),
            country=data.get("countryCode"),
            isp=data.get("isp"),
        )


class Enricher:
    """Caches lookups from one provider for the duration of an analysis run."""

    def __init__(self, mode: str, api_key: str | None = None) -> None:
        self.mode = mode
        if mode == "mock":
            self._provider = MockProvider()
        elif mode == "abuseipdb":
            self._provider = AbuseIPDBProvider(api_key or "")
        elif mode == "off":
            self._provider = None
        else:
            raise ValueError(f"Unknown enrichment mode: {mode!r}")
        self._cache: dict[str, Reputation] = {}

    def lookup(self, ip: str) -> Reputation | None:
        if self._provider is None:
            return None
        if ip not in self._cache:
            self._cache[ip] = self._provider.lookup(ip)
        return self._cache[ip]

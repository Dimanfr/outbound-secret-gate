"""Outbound secret gate: stop an AI-drafted message from revealing access codes
(door code, Wi-Fi password, key-safe PIN) to a guest who has no right to them yet.

The gate runs as the last step before a message is sent. It compares the
outgoing text with every secret known for the property and allows a match only
inside the guest's access window. When anything needed for the decision is
missing or doubtful, the message is not sent ("fail closed").

    secrets = collect_secrets(access_doc_text, secret_map=None)
    decision = check_outgoing(text, secrets, booking, now, window_hours=24)
    if not decision.allowed: ...  # route to a human, log decision.reason

Only the number of matches is ever reported, never the matched values.
Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

SECRET_MIN = 4   # bold values: shorter normalized values are ignored (too many false matches)
KEYED_MIN = 3    # values right after a keyword ("PIN: 482") may be 3 characters

# Words that introduce a secret. Compound forms count too: "Türcode", "Wi-Fi-Passwort".
_KEYWORD = re.compile(
    r"(?i)(?<![\w])[\w-]*?(?:wi-?fi|wlan|ssid|password|passwort|kennwort|pin|code|kode|"
    r"schlüssel|tür|door|netz(?:werk)?|network)[\w-]*"
)
# The keywords themselves are never secrets.
KEYWORD_WORDS = {"wifi", "wlan", "ssid", "password", "passwort", "kennwort", "pin", "code", "kode",
                 "schlüssel", "tür", "door", "netz", "netzwerk", "network"}
_QUALIFIER = r"[^\W\d_]+"  # a plain word between keyword and value: "code of the door", "Code der Haustür"
_MIXED_CASE = re.compile(r"[a-zäöüß].*[A-ZÄÖÜ]")
_DIGIT = re.compile(r"\d")

MAP_KEYS = {"label", "values", "hold", "access_doc_sha256", "extractor_sha256", "created_at"}


class SecretsUnavailable(Exception):
    """The secret list for a property cannot be trusted. Every send for it is refused."""


def normalize(value: str) -> str:
    """Compare secrets without spaces or dashes and without case: "48 21" == "4821"."""
    return re.sub(r"[\s\-‐-―]+", "", str(value or "")).casefold()


def keyed_values(text: str) -> list[str]:
    """Values written after a keyword, with up to two qualifier words in between.

    With a separator (":", "—", " - ") or quotes any value counts. Without them
    the value must contain a digit or mixed case, so ordinary prose such as
    "the door code is with the manager" yields nothing.
    """
    found = []
    for m in _KEYWORD.finditer(text):
        rest = text[m.end():m.end() + 200]
        for q in range(3):
            mm = re.match(r"(?:\s+" + _QUALIFIER + r"){" + str(q) + r"}\s*(:|—|–|\s-\s)?\s*([\"«„'“]?)([^\s«»\"'“”„,;()]+)", rest)
            if not mm:
                continue
            sep, quote, token = mm.group(1), mm.group(2), mm.group(3).rstrip(".!?")
            n = normalize(token)
            if len(n) < KEYED_MIN or n in KEYWORD_WORDS:
                continue
            if sep or quote or _DIGIT.search(token) or _MIXED_CASE.search(token):
                found.append(token)
                break
    return found


def bold_values(text: str) -> list[str]:
    """Markdown **bold** values that look like secrets: a digit, mixed case, or a keyword just before them.

    Bold labels ending in ":" ("**Door code:**") are skipped.
    """
    found = []
    for line in text.splitlines():
        for m in re.finditer(r"\*\*([^*\n]+)\*\*", line):
            value = m.group(1)
            if value.strip().endswith(":"):
                continue
            before = re.sub(r"\*\*", "", line[max(0, m.start() - 60):m.start()])
            if _KEYWORD.search(before) or _DIGIT.search(value) or _MIXED_CASE.search(value):
                found.append(value)
    return found


def load_secret_map(path: Path, access_doc: bytes) -> set[str]:
    """Read an explicit secret list written by a trusted extractor and bound to one version of the access document.

    Refuses (SecretsUnavailable) when the file is missing, malformed, on hold,
    or made for a different version of the access document.
    """
    if not path.exists():
        raise SecretsUnavailable("no secret map for this access document")
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError
        d = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(d, dict) or set(d) != MAP_KEYS:
            raise ValueError
        values, hold, doc_sha = d["values"], d["hold"], d["access_doc_sha256"]
        if (not isinstance(values, list) or not all(isinstance(v, str) for v in values)
                or not (hold is None or (isinstance(hold, str) and hold.strip()))
                or not (isinstance(doc_sha, str) and re.fullmatch(r"[0-9a-f]{64}", doc_sha))
                or not (d["extractor_sha256"] is None
                        or (isinstance(d["extractor_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", d["extractor_sha256"])))
                or not isinstance(d["created_at"], str) or not isinstance(d["label"], str)):
            raise ValueError
    except (OSError, ValueError, UnicodeDecodeError):
        raise SecretsUnavailable("secret map is malformed") from None
    if hold is not None:
        raise SecretsUnavailable("secret map is on hold")
    if doc_sha != hashlib.sha256(access_doc).hexdigest():
        raise SecretsUnavailable("secret map is stale: the access document changed")
    normalized = [normalize(v) for v in values]
    if any(len(v) < KEYED_MIN for v in normalized):
        raise SecretsUnavailable("secret map has a value shorter than 3 characters")
    return set(normalized)


def collect_secrets(access_doc: str | None, secret_map: Path | None = None, require_map: bool = False) -> set[str]:
    """All normalized secret values for one property.

    access_doc: the property's access instructions (Markdown) or None if there are none.
    secret_map: optional explicit list from a trusted extractor (see load_secret_map).
    require_map: when True, a property with an access document but no valid map is refused.
    """
    if access_doc is None:
        return set()
    values = {v for v in (normalize(x) for x in bold_values(access_doc))
              if len(v) >= SECRET_MIN and v not in KEYWORD_WORDS}
    values |= {v for v in (normalize(x) for x in keyed_values(access_doc.replace("**", "")))
               if len(v) >= KEYED_MIN and v not in KEYWORD_WORDS}
    if secret_map is not None or require_map:
        if secret_map is None:
            raise SecretsUnavailable("no secret map for this access document")
        values |= load_secret_map(secret_map, access_doc.encode("utf-8"))
    return values


@dataclass(frozen=True)
class Booking:
    status: str          # "confirmed", "cancelled", ...
    check_in: datetime   # timezone-aware
    check_out: datetime  # timezone-aware


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matches: int  # how many distinct secrets appear in the text; never the values


def access_allowed(booking: Booking | None, now: datetime, window_hours: int) -> bool:
    """A confirmed guest may receive access data from `window_hours` before check-in until check-out."""
    if booking is None or booking.status != "confirmed":
        return False
    return booking.check_in - timedelta(hours=window_hours) <= now <= booking.check_out


def check_outgoing(text: str, secrets: set[str] | None, booking: Booking | None, now: datetime,
                   window_hours: int = 24) -> Decision:
    """Decide whether `text` may be sent to the guest.

    secrets=None means "the secret list could not be read" and refuses every message.
    """
    if secrets is None:
        return Decision(False, "secrets unavailable: all sends for this property are closed", 0)
    flat = normalize(text)
    matches = sum(1 for s in secrets if s in flat)
    if matches == 0:
        return Decision(True, "no access data in the text", 0)
    if access_allowed(booking, now, window_hours):
        return Decision(True, "access data inside the guest's access window", matches)
    return Decision(False, "access data outside the guest's access window", matches)


def gate(text: str, access_doc: str | None, booking: Booking | None, now: datetime, window_hours: int = 24,
         secret_map: Path | None = None, require_map: bool = False) -> Decision:
    """One call for the common case: collect the secrets, then check the text. Fails closed."""
    try:
        secrets = collect_secrets(access_doc, secret_map, require_map)
    except SecretsUnavailable as e:
        return Decision(False, f"secrets unavailable: {e}", 0)
    return check_outgoing(text, secrets, booking, now, window_hours)

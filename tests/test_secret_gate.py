import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import secret_gate as g

ROOT = Path(__file__).resolve().parents[1]
ACCESS = (ROOT / "examples" / "access_A-101.md").read_text(encoding="utf-8")
UTC = timezone.utc

BOOKING = g.Booking("confirmed", datetime(2026, 11, 20, 15, 0, tzinfo=UTC), datetime(2026, 11, 23, 11, 0, tzinfo=UTC))
BEFORE_WINDOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)   # 51 h before check-in
IN_WINDOW = datetime(2026, 11, 19, 18, 0, tzinfo=UTC)       # 21 h before check-in
AFTER_STAY = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


class ExtractionTest(unittest.TestCase):
    def test_example_document(self):
        self.assertEqual(g.collect_secrets(ACCESS), {"4821", "739", "musterguest", "sunflowerevening7"})

    def test_prose_without_a_value_yields_nothing(self):
        self.assertEqual(g.keyed_values("The door code is with the manager."), [])
        self.assertEqual(g.keyed_values("Ask us for the Wi-Fi password at check-in."), [])

    def test_compound_german_keywords(self):
        self.assertEqual(g.keyed_values("Türcode 4821"), ["4821"])
        self.assertEqual(g.keyed_values("WLAN-Passwort: Sonnenblume"), ["Sonnenblume"])

    def test_bold_label_is_not_a_secret(self):
        self.assertEqual(g.bold_values("**Door code:** see below"), [])
        self.assertEqual(g.bold_values("Code **7391**"), ["7391"])
        self.assertEqual(g.bold_values("**Welcome**"), [])  # plain word: no digit, no mixed case, no keyword before

    def test_short_values_ignored(self):
        self.assertEqual(g.collect_secrets("Code **12**"), set())
        self.assertEqual(g.collect_secrets("PIN: 48"), set())


class GateTest(unittest.TestCase):
    def test_text_without_secrets_is_allowed(self):
        d = g.gate("Check-in is from 15:00. See you soon!", ACCESS, BOOKING, BEFORE_WINDOW)
        self.assertTrue(d.allowed)
        self.assertEqual(d.matches, 0)

    def test_secret_before_window_is_blocked(self):
        d = g.gate("Your door code is 4821.", ACCESS, BOOKING, BEFORE_WINDOW)
        self.assertFalse(d.allowed)
        self.assertEqual(d.matches, 1)

    def test_secret_inside_window_is_allowed(self):
        d = g.gate("Your door code is 4821.", ACCESS, BOOKING, IN_WINDOW)
        self.assertTrue(d.allowed)

    def test_secret_after_stay_is_blocked(self):
        self.assertFalse(g.gate("Code 4821", ACCESS, BOOKING, AFTER_STAY).allowed)

    def test_spacing_dashes_and_case_do_not_hide_a_secret(self):
        for text in ["code 48 21", "code 4-8-2-1", "pw: SUNFLOWER-evening7", "wifi sunflower evening 7"]:
            with self.subTest(text=text):
                self.assertFalse(g.gate(text, ACCESS, BOOKING, BEFORE_WINDOW).allowed)

    def test_no_booking_or_cancelled_booking_blocks(self):
        cancelled = g.Booking("cancelled", BOOKING.check_in, BOOKING.check_out)
        self.assertFalse(g.gate("Code 4821", ACCESS, None, IN_WINDOW).allowed)
        self.assertFalse(g.gate("Code 4821", ACCESS, cancelled, IN_WINDOW).allowed)

    def test_reason_never_contains_the_value(self):
        d = g.gate("Your door code is 4821.", ACCESS, BOOKING, BEFORE_WINDOW)
        self.assertNotIn("4821", d.reason)

    def test_unreadable_secrets_close_everything(self):
        d = g.check_outgoing("Hello!", None, BOOKING, IN_WINDOW)
        self.assertFalse(d.allowed)

    def test_property_without_access_document(self):
        self.assertTrue(g.gate("Code 4821", None, BOOKING, BEFORE_WINDOW).allowed)

    def test_known_limit_value_inside_a_longer_number_still_matches(self):
        # Substring matching is deliberate: better a false stop than a leak.
        self.assertFalse(g.gate("Booking reference 948217", ACCESS, BOOKING, BEFORE_WINDOW).allowed)


class SecretMapTest(unittest.TestCase):
    def write_map(self, d: Path, **overrides) -> Path:
        m = {"label": "extractor output for A-101", "values": ["Garage-77"], "hold": None,
             "access_doc_sha256": hashlib.sha256(ACCESS.encode("utf-8")).hexdigest(),
             "extractor_sha256": None, "created_at": "2026-11-11T10:00:00Z"}
        m.update(overrides)
        p = d / "secrets.json"
        p.write_text(json.dumps(m), encoding="utf-8")
        return p

    def test_map_values_are_added(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.write_map(Path(d))
            self.assertIn("garage77", g.collect_secrets(ACCESS, p))
            self.assertFalse(g.gate("garage 77", ACCESS, BOOKING, BEFORE_WINDOW, secret_map=p).allowed)

    def test_stale_held_or_malformed_map_closes_all_sends(self):
        cases = {
            "stale": dict(access_doc_sha256="0" * 64),
            "hold": dict(hold="re-check after edit"),
            "short value": dict(values=["ab"]),
            "bad type": dict(values="Garage-77"),
        }
        with tempfile.TemporaryDirectory() as d:
            for name, kw in cases.items():
                with self.subTest(name):
                    p = self.write_map(Path(d), **kw)
                    dec = g.gate("Hello, see you soon!", ACCESS, BOOKING, IN_WINDOW, secret_map=p)
                    self.assertFalse(dec.allowed)
                    self.assertTrue(dec.reason.startswith("secrets unavailable"))
            extra = Path(d) / "extra.json"
            extra.write_text(json.dumps({"label": "", "values": [], "hold": None, "access_doc_sha256": "0" * 64,
                                         "extractor_sha256": None, "created_at": "", "surprise": 1}))
            self.assertFalse(g.gate("Hi", ACCESS, BOOKING, IN_WINDOW, secret_map=extra).allowed)

    def test_required_map_missing_closes_all_sends(self):
        d = g.gate("Hello!", ACCESS, BOOKING, IN_WINDOW, require_map=True)
        self.assertFalse(d.allowed)
        with tempfile.TemporaryDirectory() as tmp:
            d2 = g.gate("Hello!", ACCESS, BOOKING, IN_WINDOW, secret_map=Path(tmp) / "missing.json")
            self.assertFalse(d2.allowed)


if __name__ == "__main__":
    unittest.main()

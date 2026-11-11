# outbound-secret-gate

A last check before an AI-drafted message goes to a guest: does the text
contain an access secret (door code, key-safe PIN, Wi-Fi password), and is
this guest allowed to receive it **now**? If not, the message is not sent and
a person takes over.

Standard-library Python, one module, no network.

## Why it was built

In a holiday-rental setting an AI assistant answers guest questions from the
property's documentation, and that documentation includes how to get in.
A guest who books for next month and asks "how do I get in?" must not receive
the door code today. The same applies to a cancelled booking, or to a code
that appears inside a longer draft. Prompt rules alone are not enough, so this
is a deterministic check that runs after the model and before sending.

## How it works

```
access document (Markdown)  ──►  collect_secrets()  ──►  normalized secrets
  + optional secret map                                       │
                                                              ▼
outgoing text, booking, now  ─────────────────────►  check_outgoing()  ──►  Decision(allowed, reason, matches)
```

**Collecting secrets** from the property's access document:

- values written after a keyword (EN/DE: *code, PIN, password, Wi-Fi, WLAN,
  SSID, door, Türcode, Passwort, …*), with up to two words in between. With a
  separator or quotes any value counts. Without them the value must contain a
  digit or mixed case, so prose such as "the door code is with the manager"
  yields nothing;
- `**bold**` values that contain a digit or mixed case, or follow a keyword.
  Bold labels ending in `:` are skipped.

**Optional secret map.** An extractor you trust can write an explicit list
of values to a JSON file that is bound to one version of the access document
by its SHA-256. If the map is missing (when required), malformed, on hold, or
made for an older version of the document, every send for that property is
refused until the map is renewed.

**Checking** the outgoing text:

- text and secrets are compared without spaces, dashes or case, so `48 21`
  and `4-8-2-1` still match `4821`;
- no match → allowed;
- a match is allowed only for a confirmed booking, from `window_hours` before
  check-in until check-out;
- no booking data, or secrets that cannot be read → refused.

The decision reports how many secrets matched, never which ones, so logs stay
free of access data.

```python
from datetime import datetime, timezone
import secret_gate as g

booking = g.Booking("confirmed",
                    datetime(2026, 11, 20, 15, tzinfo=timezone.utc),
                    datetime(2026, 11, 23, 11, tzinfo=timezone.utc))
doc = open("examples/access_A-101.md", encoding="utf-8").read()

g.gate("Your door code is 4821.", doc, booking, now=datetime(2026, 11, 18, 12, tzinfo=timezone.utc))
# Decision(allowed=False, reason="access data outside the guest's access window", matches=1)
```

## Run the tests

```sh
python3 -m unittest discover -s tests -t . -v
```

`examples/access_A-101.md` is a fictional apartment.

## Status

| | |
|---|---|
| **Original use** | Part of the send gate of an AI guest-messaging pilot for a holiday-rental operator (2026), together with a human approval step for every reply. In the pilot no message was sent to a guest, so this check was exercised on test data and synthetic apartments, not on a live send. |
| **This public example** | A standalone rewrite with English/German keywords, the optional secret map, and 18 tests on a fictional apartment (11/2026). |

## Authorship

I define requirements, coordinate AI coding agents, test behaviour and operate the resulting systems; the agents implement the code.

For this check: I set the rule that access data goes to a guest only inside
the access window, and that unclear cases are not sent.

## Limitations

- Keyword and bold-text extraction is a heuristic. A secret written in an
  unusual way can be missed, which is why the explicit secret map exists.
- Substring matching is deliberate and gives false stops. A code that is part
  of a longer number (a booking reference, say) blocks the message.
  For this use a false stop is better than a leak.
- It does not detect paraphrases ("the first two digits are 4 and 8") or
  values that a model invents.
- It is a gate, not a replacement for human approval of outgoing messages.

## Licence

MIT, see `LICENSE`.

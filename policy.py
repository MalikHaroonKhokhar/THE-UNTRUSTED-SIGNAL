"""Reference decision policy for the Airosea untrusted-signal evaluation pack.

decide(case) reads one case (one or more connector events) and returns a decision record.
It is offline, deterministic and uses the standard library only.

Trust model: payload content is a claim, never authority. Trust comes only from the envelope
fields the adapter recorded (provenance, received_at, connector) and from fields a verified
signature covers. There are no vehicle or resolution actions, so an instruction hidden in a
ticket has nothing to map to.

Usage: python3 policy.py fixtures/events.jsonl
"""
import base64
import hashlib
import json
import logging
import re
import sys
import unicodedata
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from itertools import combinations

log = logging.getLogger("policy")

# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------

DISPOSITIONS = ("ACCEPT", "POSSIBLE_DUPLICATE", "NEEDS_REVIEW", "QUARANTINE")  # least to most strict

# The complete action list, in priority order. This list is the security boundary: there is
# no unlock, OTA, rollback, close, merge or export action for an injected instruction to reach.
ACTIONS = (
    "quarantine_hold_verify_via_known_channel",
    "keep_incident_open",
    "hold_for_human_review",
    "recommend_security_review",
    "advise_credential_rotation",
    "link_as_candidate",
    "draft_incident_for_oncall",
)
BASE_ACTION = {
    "ACCEPT": "draft_incident_for_oncall",
    "POSSIBLE_DUPLICATE": "link_as_candidate",
    "NEEDS_REVIEW": "hold_for_human_review",
    "QUARANTINE": "quarantine_hold_verify_via_known_channel",
}

# code -> (minimum disposition, action it adds or None, fixed note)
REASONS = {
    "MALFORMED_ENVELOPE": ("QUARANTINE", None, "The event envelope is not in the expected shape."),
    "MALFORMED_PAYLOAD": ("QUARANTINE", None, "The payload could not be parsed; no content was trusted."),
    "UNKNOWN_CONNECTOR": ("QUARANTINE", None, "The connector is not recognised by this policy."),
    "UNVERIFIED_SOURCE": ("QUARANTINE", None, "The source could not be verified by the adapter."),
    "PROVENANCE_INCONSISTENT": ("QUARANTINE", None, "The provenance method does not fit this connector."),
    "MISSING_SOURCE_IDENTITY": ("QUARANTINE", None, "The sender identity is missing."),
    "MISSING_OCCURRED_AT": ("QUARANTINE", None, "The event time is missing; receipt time was not substituted."),
    "INVALID_TIMESTAMP": ("QUARANTINE", None, "A timestamp is invalid or has no timezone."),
    "MISSING_SOURCE_EVENT_ID": ("NEEDS_REVIEW", None, "The source event ID is missing; deduplication is not possible."),
    "ID_UNTRUSTED_FORMAT": ("NEEDS_REVIEW", None, "An identifier did not match its expected format and was dropped."),
    "CLOCK_SKEW": ("NEEDS_REVIEW", None, "The event time is later than the receipt time."),
    "PII_REDACTED": ("ACCEPT", None, "Personal data was masked; the diagnosis was kept."),
    "SECRET_SHAPED_VALUE": ("NEEDS_REVIEW", "advise_credential_rotation", "A credential-shaped value was masked and never used."),
    "INJECTION_REJECTED": ("NEEDS_REVIEW", "recommend_security_review", "The content contained instructions; content has no authority and was not followed."),
    "UNSOLICITED_ACTION_REQUEST": ("NEEDS_REVIEW", None, "The event requests an operational action; actions are never taken from event content."),
    "STALE_STATE_IGNORED": ("ACCEPT", None, "An update older than the current state was ignored."),  # action set by the check
    "TIMELINE_CONFLICT": ("NEEDS_REVIEW", None, "Event ordering could not be established; current state is unconfirmed."),
    "DUPLICATE_DELIVERY": ("ACCEPT", None, "The same signed event was delivered more than once."),
    "ID_COLLISION": ("NEEDS_REVIEW", None, "The same ID arrived with different content; nothing was deduplicated."),
    "THREAD_RELATION_ASSERTED": ("POSSIBLE_DUPLICATE", "link_as_candidate", "The messages claim to be related through sender-controlled headers."),
    "NEW_INFORMATION": ("POSSIBLE_DUPLICATE", None, "A related message adds information not in the original."),
    "UNPROVEN_CORRELATION": ("NEEDS_REVIEW", "link_as_candidate", "These events may describe the same problem; no shared identifier proves it."),
    "POLICY_ERROR": ("QUARANTINE", None, "The policy could not evaluate this event."),
    "OUTPUT_GUARD_TRIPPED": ("QUARANTINE", None, "The decision failed its output safety check and was replaced."),
}

OUTPUT_KEYS = (
    "case_id", "disposition", "reason_codes", "evidence_refs", "safe_next_action",
    "additional_actions", "human_review_required", "redaction_requirements",
    "notes_on_uncertainty", "observed_state", "summary",
)

# The only diagnosis wording a summary may contain.
GLOSSARY = (
    ("CN-503", "CN-503 vehicle unreachable"),
    ("BK-402", "BK-402 booking payment error"),
    ("HTTP 401", "HTTP 401 unauthorised"),
    ("AD-117", "AD-117 diagnostic session timeout"),
)

ENVELOPE_KEYS = ("event_ref", "connector", "source_event_id", "occurred_at", "received_at", "provenance", "payload")
INTERNAL_DOMAIN = "airosea.example"
CLOCK_SKEW_LIMIT = timedelta(seconds=300)
CORRELATION_WINDOW = timedelta(minutes=30)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

JIRA_STATES = ("To Do", "Open", "In Progress", "Resolved", "Reopened", "Closed", "Done")
SNS_STATES = ("OK", "ALARM", "INSUFFICIENT_DATA")
ACTIVE_STATES = ("ALARM", "Reopened", "Open", "In Progress")

# `[0-9]`, not `\d`: in Python `\d` also matches non-ASCII digits such as "٣".
# fullmatch() is used everywhere, so a trailing newline cannot sneak past `$`.
CASE_ID = re.compile(r"AIR-[0-9]{2}[a-z0-9-]*")  # "AIR-08-repaired" yes; "AIR-8" no
EVENT_REF = re.compile(r"e[0-9]{1,3}")  # "e1" yes; "e1:payload" no
MESSAGE_ID = r"<[^<>@\s]+@[^<>@\s]+>"  # "<abc.1@host.example>" yes; "abc@host" (no brackets) no
LOWER_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # uppercase UUIDs are rejected

# ---------------------------------------------------------------------------
# Connector table: one row per connector. Adding a connector is adding a row.
#   method     the only provenance method accepted for this connector
#   time       (path, format) of the one field that gives the event time
#   id         (path, pattern) of the source event ID
#   free_text  fields that are redacted and scanned for injection
#   pii        fields masked whole, by name
#   signed     fields hashed for deduplication (transport metadata excluded)
#   attested   fields the platform itself generates and the verification covers;
#              cited as "observed" when the event is verified, else "asserted"
#   json       string fields that must parse as a JSON object
#   state      where a state change (from -> to) is read, the states it may take, and (Jira) the
#              status snapshot every event carries
#   thread     Graph thread headers (sender-controlled) used to spot forwards and replies
#   retry      a transport header that marks a redelivery
# ---------------------------------------------------------------------------

CONNECTORS = {
    "imap": {
        "method": "dkim",
        "time": ("payload.headers[name=Date]", "rfc2822"),
        "id": ("payload.headers[name=Message-ID]", MESSAGE_ID),
        "free_text": ("payload.headers[name=Subject]", "payload.body"),
        "pii": ("payload.headers[name=From]",),
        "signed": ("payload.headers[name=Message-ID]", "payload.body"),
        "attested": (),
    },
    "graph": {
        "method": "oauth_api_pull",
        "time": ("payload.sentDateTime", "iso"),
        "id": ("payload.internetMessageId", MESSAGE_ID),
        "free_text": ("payload.subject", "payload.body.content", "payload.uniqueBody.content"),
        "pii": ("payload.from.emailAddress.address", "payload.from.emailAddress.name"),
        "signed": ("payload.internetMessageId", "payload.body.content"),
        "attested": (),
        "thread": {"id": "payload.conversationId", "index": "payload.conversationIndex",
                   "new_text": "payload.uniqueBody.content", "full_text": "payload.body.content"},
    },
    "jira": {
        "method": "hmac_sha256",
        "time": ("payload.body.timestamp", "epoch_ms"),
        "id": ("payload.headers.X-Atlassian-Webhook-Identifier", r"[A-Za-z0-9-]{8,64}"),
        "free_text": ("payload.body.issue.fields.summary", "payload.body.issue.fields.description",
                      "payload.body.comment.body"),
        "pii": ("payload.body.user.displayName", "payload.body.user.emailAddress",
                "payload.body.comment.author.displayName"),
        "signed": ("payload.body",),
        "attested": ("payload.body.timestamp", "payload.body.changelog", "payload.body.issue.fields.status.name"),
        "state": {"items": "payload.body.changelog.items", "snapshot": "payload.body.issue.fields.status.name",
                  "refs": ("payload.body.changelog", "payload.body.issue.fields.status.name"), "known": JIRA_STATES},
        "retry": "payload.headers.X-Atlassian-Webhook-Retry",
    },
    "zendesk": {
        "method": "oauth_api_pull",
        "time": ("payload.ticket.updated_at", "iso"),
        "id": ("payload.ticket.id", r"[0-9]+"),
        "free_text": ("payload.ticket.subject", "payload.ticket.description"),
        "pii": ("payload.requester.name", "payload.requester.email"),
        "signed": ("payload.ticket",),
        "attested": ("payload.ticket.updated_at", "payload.ticket.id"),
    },
    "salesforce": {
        "method": "oauth_api_pull",
        "time": ("payload.LastModifiedDate", "iso"),
        "id": ("payload.Id", r"500[A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?"),  # Case IDs start 500; 15 or 18 chars
        "free_text": ("payload.Subject", "payload.Description"),
        "pii": ("payload.SuppliedName", "payload.SuppliedPhone", "payload.SuppliedEmail"),
        "signed": ("payload.Id", "payload.Description"),
        "attested": ("payload.LastModifiedDate", "payload.Id"),
    },
    "cloudwatch_sns": {
        "method": "aws_sns_signature",
        "time": ("payload.body.Message#StateChangeTime", "iso"),
        "id": ("payload.body.MessageId", LOWER_UUID),
        "free_text": ("payload.body.Message#AlarmDescription", "payload.body.Message#NewStateReason"),
        "pii": (),
        "signed": ("payload.body.Message", "payload.body.MessageId", "payload.body.Subject",
                   "payload.body.Timestamp", "payload.body.TopicArn", "payload.body.Type"),
        "attested": ("payload.body.Message#StateChangeTime", "payload.body.Message#OldStateValue",
                     "payload.body.Message#NewStateValue", "payload.body.MessageId"),
        "json": ("payload.body.Message",),
        "state": {"from": "payload.body.Message#OldStateValue", "to": "payload.body.Message#NewStateValue",
                  "refs": ("payload.body.Message#OldStateValue", "payload.body.Message#NewStateValue"),
                  "known": SNS_STATES},
    },
    "webhook": {
        "method": "hmac_sha256",
        "time": ("payload.headers.X-Airosea-Timestamp", "iso"),
        "id": ("payload.headers.X-Airosea-Delivery", LOWER_UUID),
        "free_text": ("payload.raw_body",),
        "pii": (),
        "signed": ("payload.raw_body",),
        "attested": (),
        "json": ("payload.raw_body",),
    },
}

# ---------------------------------------------------------------------------
# Detection patterns. Advisory only: they can add strictness and a flag, never remove it,
# and no decision depends on them catching everything. The pattern name is the redaction kind.
# ---------------------------------------------------------------------------

SECRET_PATTERNS = tuple((kind, re.compile(pattern)) for kind, pattern in (
    # "kpfake_" + live|test + "_" + 8 or more letters/digits. Yes: kpfake_live_8Hq2ZtR4. No: kpfake_demo_8Hq2ZtR4.
    ("api_key", r"\bkpfake_(?:live|test)_[A-Za-z0-9]{8,}\b"),
    # "bearer", whitespace, then 16+ token characters, not a "<placeholder>". Yes: Bearer abcdefghijklmnop12. No: Bearer <token>.
    ("bearer_token", r"(?i)\bbearer\s+(?!<)[A-Za-z0-9\-._~+/]{16,}=*"),
    # Three base64url parts joined by dots, the first starting "eyJ" (an encoded "{"). No: eyJ.short.parts.
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # "AKIA" + 16 uppercase letters/digits (AWS access key ID shape). No: AKIA plus 15 characters.
    ("aws_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    # scheme://user:password@, each run length-capped so a huge field cannot make matching quadratic.
    # Yes: postgres://app:pw@db. No: https://host:5432/x (no "@").
    ("url_credentials", r"\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@]{1,256}:[^\s@/]{1,256}@"),
))
PII_PATTERNS = tuple((kind, re.compile(pattern)) for kind, pattern in (
    # local@domain.tld, with RFC length caps. Yes: farah@inbox-mail.example. No: farah@localhost (no dot-TLD).
    ("email", r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b"),
    # +country code then three digit groups, not glued to other word characters. Yes: +92 321 0005678. No: 0321 0005678 (no "+").
    ("phone", r"(?<![\w-])\+\d{1,3}[\s-]?\d{3}[\s-]?\d{3,4}[\s-]?\d{3,4}(?![\w-])"),
    # 17 VIN characters (I, O and Q are never used). Yes: 1HGBH41JXMN109186. No: a 17-character run containing an O.
    ("vin", r"\b[A-HJ-NPR-Z0-9]{17}\b"),
))
PII_KINDS = {kind for kind, _ in PII_PATTERNS} | {"pii_field"}
SECRET_KINDS = {kind for kind, _ in SECRET_PATTERNS}

# "ignore|disregard|forget|override", then within 40 chars "previous|prior|above|earlier|all",
# then within 20 chars "instructions|rules|prompts|policies". Yes: "Ignore all previous instructions". No: "ignore the noise".
INJECTION_OVERRIDE = re.compile(r"(?i)\b(ignore|disregard|forget|override)\b.{0,40}"
                                r"\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules|prompts?|policies)\b")
# A claim of special status. Yes: "You are now in admin mode". No: "the admin portal".
AUTHORITY_CLAIM = re.compile(r"(?i)(you are now|you are authori[sz]ed|admin mode|developer mode|"
                             r"system note|note to (the )?(ai|assistant)|as (an? )?(admin|administrator|system))")
# An order verb. Yes: "export", "mark this ticket solved". No: "exported" (word boundary), "Runbook".
IMPERATIVE = re.compile(r"(?i)\b(export|send|forward|delete|close|grant|disable|run|execute|push|"
                        r"roll ?back|mark\b.{0,20}\b(solved|resolved|closed))\b")
# "all|every|full|entire|complete" then within 30 chars a bulk-data noun. Yes: "all customers". No: "all stalls".
BULK_DATA = re.compile(r"(?i)\b(all|every|full|entire|complete)\b.{0,30}"
                       r"\b(customers?|users?|owners?|vins?|addresses|records|emails|export|database)\b")
# A send/export verb, then (same sentence, within 80 chars) "to" and an address; group 1 is the domain.
# Yes: "Export all customers ... to x@outside.example". No: "To: Service Ops <ops@airosea.example>" (no verb).
SEND_TO = re.compile(r"(?i)\b(?:export|send|forward|e-?mail|upload|transfer|share)\b[^.\n]{0,80}?"
                     r"\bto\s+<?[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63})")
# A fleet or infrastructure action verb aimed (within 40 chars) at vehicles or systems.
# Yes: "push immediate OTA rollback to all Strata vehicles". No: "OTA 4.2.1 stuck at 'downloading' on Strata trims".
FLEET_ACTION = re.compile(r"(?i)\b(push|roll ?back|fail ?over|run|execute|deploy)\b.{0,40}?"
                          r"\b(vehicles?|cars?|fleet|servers?|systems?|clusters?|databases?|production)\b")

# ---------------------------------------------------------------------------
# Path resolver: the one way any code (policy or tests) reads a field.
# ---------------------------------------------------------------------------

# One path step: key, optional [name=X], optional #sub. Yes: "headers[name=Date]", "Message#StateChangeTime". No: "items[0]".
STEP = re.compile(r"([^.\[\]#]+)(?:\[name=([^\]]+)\])?(?:#([^.\[\]#]+))?")


def parse_json_object(text):
    """Parse a string holding a JSON object; return the dict, or None for anything else.

    The webhook raw_body and the SNS Message are JSON inside a string, so they need this.
    """
    if not isinstance(text, str):
        return None
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):  # truncated or absurdly nested JSON is just unparseable
        return None
    return value if isinstance(value, dict) else None


def json_strings(node):
    """Every key and string value inside parsed JSON, walked with a stack rather than recursion."""
    out, stack = [], [node]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            out.extend(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            out.append(node)
    return out


def locate(root, path):
    """Find where `path` points inside `root`: return (container, key), or None if a step is missing.

    Steps are separated by "." and take three forms:
      key          dict lookup
      key[name=X]  the first item named X (case-insensitive) in a list of {"name", "value"} items
      key#sub      parse the string at key as JSON, then look up sub
    List positions are not supported on purpose, so refs stay valid when items are reordered.
    The key in the returned pair may itself be absent; resolve() then gives None.
    """
    node, steps = root, path.split(".")
    for i, step in enumerate(steps):
        match = STEP.fullmatch(step)
        if match is None or not isinstance(node, dict):
            return None
        key, name, sub = match.groups()
        container, slot = node, key
        if name is not None:
            items = node.get(key)
            if not isinstance(items, list):
                return None
            container = next((item for item in items if isinstance(item, dict)
                              and isinstance(item.get("name"), str) and item["name"].lower() == name.lower()), None)
            if container is None:
                return None
            slot = "value"
        if sub is not None:
            container, slot = parse_json_object(container.get(slot)), sub
            if container is None:
                return None
        if i == len(steps) - 1:
            return container, slot
        node = container.get(slot)
    return None


def resolve(root, path):
    """Return the value at `path`, or None if it is missing. A field holding null also counts as missing."""
    found = locate(root, path)
    return None if found is None else found[0].get(found[1])


def case_events(case):
    """The case's events that are dicts, in file order; [] if the case has no usable event list."""
    events = case.get("events") if isinstance(case, dict) else None
    return [event for event in events if isinstance(event, dict)] if isinstance(events, list) else []


def resolve_ref(case, ref):
    """Resolve an evidence ref "<event_ref>:<path>" against a case; None if it does not resolve."""
    event_ref, _, path = ref.partition(":")
    for event in case_events(case):
        if event.get("event_ref") == event_ref:
            return resolve(event, path)
    return None


def parse_time(value, fmt):
    """Parse a timestamp in the given format into aware UTC; None if invalid or it has no timezone.

    Formats: "iso" (ISO 8601), "rfc2822" (email Date header), "epoch_ms" (13-digit integer).
    A naive time is rejected rather than guessed: AIR-07 only correlates because the email's
    +0500 offset is honoured.
    """
    try:
        if fmt == "epoch_ms":
            if type(value) is not int or not 10**12 <= value < 10**13:  # `type` check rejects True/False
                return None
            return EPOCH + timedelta(milliseconds=value)
        if not isinstance(value, str):
            return None
        parsed = parsedate_to_datetime(value) if fmt == "rfc2822" else datetime.fromisoformat(value)
        if parsed.tzinfo is None:  # includes RFC 2822 "-0000", which means "zone unknown"
            return None
        return parsed.astimezone(timezone.utc)  # inside the try: year 9999 at -05:00 overflows
    except (ValueError, TypeError, IndexError, OverflowError):
        return None


def safe_case_id(case):
    """The case ID if it has the expected shape, else "UNKNOWN". Only a safe ID is ever echoed or logged."""
    case_id = case.get("case_id") if isinstance(case, dict) else None
    return case_id if isinstance(case_id, str) and CASE_ID.fullmatch(case_id) else "UNKNOWN"


def normalise(text):
    """NFKC-normalise, then drop invisible format characters (Unicode category Cf, e.g. zero-width space).

    Applied before injection matching, so "ig\u200bnore" and full-width letters cannot hide a keyword.
    """
    return "".join(ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf")


def sends_outside(text):
    """True if the text orders data sent or exported *to* an address outside airosea.example.

    Only the target of a send/export order counts. Customers all write from outside addresses,
    so merely containing one must not count.
    """
    for match in SEND_TO.finditer(text):
        domain = match.group(1).lower()
        if domain != INTERNAL_DOMAIN and not domain.endswith("." + INTERNAL_DOMAIN):
            return True
    return False

# ---------------------------------------------------------------------------
# 1. extract: the only reader of raw payload data
# ---------------------------------------------------------------------------


def extract(case):
    """Turn the raw case into typed facts. This is the only function that reads raw payload values.

    Returns ctx = {"case_id", "malformed", "events": [fact, ...]}. A fact holds parsed times, the
    validated source ID, provenance flags, the signed-field hash, state and thread facts, the refs
    that may be cited, and the free text that sanitize() and the checks scan. Only typed values and
    refs ever move from ctx into the output.
    """
    events = case.get("events") if isinstance(case, dict) else None
    ctx = {"case_id": safe_case_id(case), "malformed": not isinstance(events, list) or not events, "events": []}
    seen = set()
    for event in events if isinstance(events, list) else []:
        if not envelope_ok(event, seen):
            ctx["malformed"] = True  # an event we cannot address by ref is never analysed
            continue
        seen.add(event["event_ref"])
        ctx["events"].append(extract_event(event))
    return ctx


def envelope_ok(event, seen):
    """True if the event has exactly the envelope keys, a unique well-formed event_ref and a provenance dict.

    The envelope is our own adapter's contract, so an extra or missing key means it is not in the
    expected shape. (Extra keys inside the payload are fine and ignored.)
    """
    return (isinstance(event, dict) and set(event) == set(ENVELOPE_KEYS)
            and isinstance(event["event_ref"], str) and EVENT_REF.fullmatch(event["event_ref"]) is not None
            and event["event_ref"] not in seen and isinstance(event["provenance"], dict))


def extract_event(event):
    """Build the fact dict for one well-formed event (see extract)."""
    ref, prov = event["event_ref"], event["provenance"]
    connector = event["connector"]
    row = CONNECTORS.get(connector) if isinstance(connector, str) else None
    verified = prov.get("verified") is True  # only a real boolean True counts; the string "true" does not
    method_ok = row is not None and prov.get("method") == row["method"]
    identity = prov.get("source_identity")
    fact = {
        "ref": ref, "row": row, "connector": connector if row else None,
        "verified": verified, "method_ok": method_ok,
        "identity": identity if isinstance(identity, str) and identity.strip() else None,
        "received": parse_time(event["received_at"], "iso"),
        "envelope_time": parse_time(event["occurred_at"], "iso"),
        "envelope_time_invalid": event["occurred_at"] is not None and parse_time(event["occurred_at"], "iso") is None,
        "payload_ok": False, "time": None, "time_state": "missing", "source_id": None, "id_state": "missing",
        "hash": None, "state": None, "state_ok": False, "snapshot": None, "state_refs": [], "retry_ref": None, "thread": None,
        "cite": {}, "texts": {}, "norm": {}, "sends_outside": {}, "terms": set(), "pii": [], "other": [],
    }
    trusted = verified and method_ok

    def cite(path, kind=None):
        """Record `path` as citable if it resolves to a non-null value. Kind comes from the table unless given."""
        if path and resolve(event, path) is not None:
            if kind is None:
                kind = "observed" if trusted and path in row["attested"] else "asserted"
            fact["cite"][path] = (f"{ref}:{path}", kind)

    for path in ("provenance.verified", "provenance.method", "received_at", "connector"):
        cite(path, "observed")  # recorded by our own adapter
    for path in ("occurred_at", "source_event_id"):
        cite(path, "asserted")  # copied by the adapter from the payload
    declared = set()
    if row is not None:
        extract_declared(event, row, fact, cite, declared)
    fact["other"] = other_strings(event, ref, declared)
    return fact


def extract_declared(event, row, fact, cite, declared):
    """Read the fields the connector's row declares. Each fact has exactly one source path; nothing is substituted."""
    fact["payload_ok"] = isinstance(event["payload"], dict) and all(
        parse_json_object(resolve(event, path)) is not None for path in row.get("json", ()))

    time_path, time_format = row["time"]
    raw_time = resolve(event, time_path)
    if raw_time is not None:
        fact["time"] = parse_time(raw_time, time_format)
        fact["time_state"] = "ok" if fact["time"] else "invalid"

    # IDs and times are taken from raw data here, before any redaction runs, so masking can
    # never make two different IDs look identical.
    id_path, id_pattern = row["id"]
    raw_id = resolve(event, id_path)
    if type(raw_id) is int:  # Zendesk ticket IDs are integers
        raw_id = str(raw_id)
    if raw_id is not None:
        valid = isinstance(raw_id, str) and re.fullmatch(id_pattern, raw_id) is not None
        fact["source_id"] = raw_id if valid else None
        fact["id_state"] = "ok" if valid else "untrusted"

    # Dedupe fingerprint: the signed fields plus the declared time, free text and personal-data fields.
    # A redelivery repeats all of them; an update to the same record (a Salesforce case edit, a mail
    # re-sent from another address) changes at least one. Transport metadata stays out.
    hashed = dict.fromkeys((*row["signed"], time_path, *row["free_text"], *row["pii"]))
    try:
        signed = json.dumps([[path, resolve(event, path)] for path in hashed], sort_keys=True)
        fact["hash"] = hashlib.sha256(signed.encode()).hexdigest()
    except RecursionError:  # content nested too deeply to fingerprint is treated as unparseable
        fact["payload_ok"] = False

    for path in row["free_text"]:
        text = resolve(event, path)
        if isinstance(text, str):  # last place raw free text is read; sanitize() and the checks use these copies
            decoded = parse_json_object(text) if path in row.get("json", ()) else None
            if decoded is not None:  # also scan what a consumer reads: JSON "v\u0065hicles" is "vehicles"
                text = "\n".join([text, *json_strings(decoded)])
            fact["texts"][path] = text
            fact["norm"][path] = normalise(text)
            fact["sends_outside"][path] = sends_outside(fact["norm"][path])  # before any address is masked
            fact["terms"].update(term for term, _ in GLOSSARY if term in fact["norm"][path])
            mark_declared(event, path, declared)
    for path in row["pii"]:
        if resolve(event, path) is not None:
            fact["pii"].append(path)
            mark_declared(event, path, declared)

    state = row.get("state")
    if state:
        if "items" in state:
            items = resolve(event, state["items"])
            items = items if isinstance(items, list) else []
            status = next((item for item in items if isinstance(item, dict) and item.get("field") == "status"), None)
            change = (status.get("fromString"), status.get("toString")) if status else None
        else:  # every alarm notification is a state change, so missing values are a conflict, not "no change"
            change = (resolve(event, state["from"]), resolve(event, state["to"]))
        fact["state"] = change
        fact["snapshot"] = resolve(event, state["snapshot"]) if "snapshot" in state else None
        fact["state_ok"] = change is not None and all(value in state["known"] for value in change)
        for path in state["refs"]:
            cite(path)
        fact["state_refs"] = [fact["cite"][path] for path in state["refs"] if path in fact["cite"]]

    thread = row.get("thread")
    if thread:
        conversation, index = resolve(event, thread["id"]), resolve(event, thread["index"])
        if isinstance(conversation, str) and isinstance(index, str):
            try:
                fact["thread"] = (conversation, base64.b64decode(index, validate=True))
            except ValueError:  # not valid base64: the relation cannot even be claimed
                pass
        for path in (thread["id"], thread["index"]):
            cite(path)

    for path in (time_path, id_path, *row["free_text"], row.get("retry")):
        cite(path)
    fact["retry_ref"] = fact["cite"].get(row.get("retry"))


def mark_declared(event, path, declared):
    """Remember where a free-text or PII field lives, so the generic secret scan does not report it again.

    A field inside a JSON string (the SNS Message) cannot be skipped this way: the whole string is
    still scanned, so a secret there is also reported against the section ("e1:payload").
    """
    found = locate(event, path)
    if found is not None:
        declared.add((id(found[0]), found[1]))


def other_strings(event, ref, declared):
    """Every string value and dict key not already handled as free text or PII, paired with the ref to report it under.

    Keys inside the payload are attacker-controlled, so a ref never includes them: a hit is
    reported against its whole section ("e1:payload", "e1:provenance") instead.
    """
    out = []
    for key in ENVELOPE_KEYS:
        section = f"{ref}:{key}"
        if isinstance(event[key], str):
            out.append((section, event[key]))
        else:
            walk_strings(event[key], section, declared, out)
    return out


def walk_strings(root, section, declared, out):
    """Collect (section, string) for every dict key and string value below `root`, skipping declared fields.

    Uses a stack rather than recursion, so a deeply nested payload cannot exhaust the recursion limit.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            out.extend((section, key) for key in node if isinstance(key, str))
            pairs = node.items()
        elif isinstance(node, list):
            pairs = enumerate(node)
        else:
            continue
        for slot, value in pairs:
            if isinstance(value, str):
                if (id(node), slot) not in declared:
                    out.append((section, value))
            else:
                stack.append(value)

# ---------------------------------------------------------------------------
# 2. sanitize: where must something be masked?
# ---------------------------------------------------------------------------


def sanitize(ctx):
    """Return every place a value must be masked, as a sorted list of {ref, kind}.

    PII fields are masked whole, by name. In free text, secrets are masked first and personal data
    is then looked for in the masked text: AIR-08's "user:password@host" would otherwise look like
    an email address. Every other string and key is scanned for secrets only. One entry per place
    and kind, however many matches. No value is stored or returned.
    """
    found = set()
    for fact in ctx["events"]:
        found.update((f"{fact['ref']}:{path}", "pii_field") for path in fact["pii"])
        for path, text in fact["texts"].items():
            ref = f"{fact['ref']}:{path}"
            for kind, pattern in SECRET_PATTERNS:
                text, count = pattern.subn("[masked]", text)
                if count:
                    found.add((ref, kind))
            found.update((ref, kind) for kind, pattern in PII_PATTERNS if pattern.search(text))
        for ref, text in fact["other"]:
            found.update((ref, kind) for kind, pattern in SECRET_PATTERNS if pattern.search(text))
    return [{"ref": ref, "kind": kind} for ref, kind in sorted(found)]

# ---------------------------------------------------------------------------
# 3. Checks. Each reads only ctx and returns every finding it has.
# ---------------------------------------------------------------------------


def finding(code, refs=(), actions=None):
    """One finding: a reason code, the (ref, kind) pairs behind it, and the actions it adds (default from REASONS)."""
    if actions is None:
        actions = [REASONS[code][1]] if REASONS[code][1] else []
    return {"code": code, "refs": [ref for ref in refs if ref], "actions": actions}


def check_envelope(ctx):
    """Malformed envelope, unknown connector, or a payload that cannot be parsed for its connector (AIR-08)."""
    out = [finding("MALFORMED_ENVELOPE")] if ctx["malformed"] else []
    for fact in ctx["events"]:
        if fact["row"] is None:
            out.append(finding("UNKNOWN_CONNECTOR", [fact["cite"].get("connector")]))
        elif not fact["payload_ok"]:
            out.append(finding("MALFORMED_PAYLOAD"))
    return out


def check_provenance(ctx):
    """Every provenance and timing defect of every event, not just the first (AIR-08 has four of them)."""
    out = []
    for fact in ctx["events"]:
        cite, row = fact["cite"], fact["row"]
        if not fact["verified"]:
            out.append(finding("UNVERIFIED_SOURCE", [cite.get("provenance.verified"), cite.get("provenance.method")]))
        elif row is not None and not fact["method_ok"]:
            out.append(finding("PROVENANCE_INCONSISTENT", [cite.get("provenance.method")]))
        if fact["identity"] is None:
            out.append(finding("MISSING_SOURCE_IDENTITY"))
        if fact["received"] is None or fact["envelope_time_invalid"]:
            out.append(finding("INVALID_TIMESTAMP", [cite.get("received_at"), cite.get("occurred_at")]))
        if row is None:
            continue
        time_ref, id_ref = cite.get(row["time"][0]), cite.get(row["id"][0])
        if fact["time_state"] == "missing":
            out.append(finding("MISSING_OCCURRED_AT"))  # never filled in from received_at or occurred_at
        elif fact["time_state"] == "invalid":
            out.append(finding("INVALID_TIMESTAMP", [time_ref]))
        elif fact["envelope_time"] is not None and fact["envelope_time"] != fact["time"]:
            out.append(finding("TIMELINE_CONFLICT", [time_ref, cite.get("occurred_at")]))
        if fact["id_state"] == "missing":
            out.append(finding("MISSING_SOURCE_EVENT_ID"))
        elif fact["id_state"] == "untrusted":
            out.append(finding("ID_UNTRUSTED_FORMAT", [id_ref]))
        if fact["time"] and fact["received"] and fact["time"] - fact["received"] > CLOCK_SKEW_LIMIT:
            out.append(finding("CLOCK_SKEW", [time_ref, cite.get("received_at")]))
    return out


def check_sensitive(ctx):
    """PII_REDACTED and SECRET_SHAPED_VALUE from the redactions sanitize() recorded (AIR-05)."""
    kinds = {item["kind"] for item in ctx["redactions"]}
    out = [finding("PII_REDACTED")] if kinds & PII_KINDS else []
    if kinds & SECRET_KINDS:
        out.append(finding("SECRET_SHAPED_VALUE"))
    return out


def check_injection(ctx):
    """Instructions in free text are flagged, never followed (AIR-04). Detection only ever adds strictness.

    INJECTION_REJECTED when: the override pattern matches; or an authority claim and an order both
    match; or a bulk-data request and an order both match and the text sends it to an outside
    address. Otherwise UNSOLICITED_ACTION_REQUEST when the text orders a fleet or infrastructure action.
    """
    out = []
    for fact in ctx["events"]:
        for path, text in fact["norm"].items():
            order = IMPERATIVE.search(text)
            if (INJECTION_OVERRIDE.search(text)
                    or (order and AUTHORITY_CLAIM.search(text))
                    or (order and BULK_DATA.search(text) and fact["sends_outside"][path])):
                out.append(finding("INJECTION_REJECTED", [fact["cite"].get(path)]))
            elif FLEET_ACTION.search(text):
                out.append(finding("UNSOLICITED_ACTION_REQUEST", [fact["cite"].get(path)]))
    return out


def check_stale_state(ctx):
    """Work out the current state from event time, never arrival order (AIR-03, AIR-06).

    Order the state changes by event time. If each one's previous state equals the prior one's new
    state, the chain is consistent: the current state is the newest new state, and any event that
    arrived after a newer one is stale and ignored. A broken chain, an unknown state, or two
    different changes at the same time is a TIMELINE_CONFLICT and leaves the state unconfirmed.
    Identical changes (a redelivery) collapse into one. A change whose time is after its own receipt
    cannot be placed, and a newer event whose status snapshot disagrees with the chain (a Jira
    priority edit made after a reopen we never received) means a change is missing: both conflict.
    """
    changes = [fact for fact in ctx["events"] if fact["state"] is not None]
    if not changes:
        return []
    refs = [ref for fact in changes for ref in fact["state_refs"]]
    conflict = [finding("TIMELINE_CONFLICT", refs)]
    if any(not fact["state_ok"] or fact["time"] is None
           or (fact["received"] is not None and fact["time"] - fact["received"] > CLOCK_SKEW_LIMIT)
           for fact in changes):
        return conflict
    chain = sorted({(fact["time"], fact["state"]) for fact in changes})
    if len({time for time, _ in chain}) != len(chain):
        return conflict
    if any(later[1][0] != earlier[1][1] for earlier, later in zip(chain, chain[1:])):
        return conflict
    current, newest = chain[-1][1][1], chain[-1][0]
    disagree = [fact for fact in ctx["events"] if fact["snapshot"] is not None and fact["time"] is not None
                and fact["time"] >= newest and fact["snapshot"] != current]
    if disagree:
        return [finding("TIMELINE_CONFLICT", refs + [ref for fact in disagree for ref in fact["state_refs"]])]
    ctx["observed_state"] = current
    stale = [old for old in changes if any(
        new["time"] > old["time"] and old["received"] and new["received"] and old["received"] > new["received"]
        for new in changes)]
    if not stale:
        return []
    keep_open = ["keep_incident_open"] if current in ACTIVE_STATES else []  # an active incident is never closed by a late update
    return [finding("STALE_STATE_IGNORED", refs + [fact["retry_ref"] for fact in stale], keep_open)]


def check_duplicates(ctx):
    """Deduplicate only on proof (AIR-06), and only claim a thread relation for forwards and replies (AIR-02).

    Same connector, identity, source ID and signed-field hash: DUPLICATE_DELIVERY. Same source ID but
    a different hash: ID_COLLISION, and nothing in that group is deduplicated. Different IDs in the
    same Graph conversation where one conversationIndex extends the other: THREAD_RELATION_ASSERTED,
    plus NEW_INFORMATION unless the child's uniqueBody is provably already in the parent's body.
    """
    out, groups = [], {}
    for fact in ctx["events"]:
        if fact["source_id"] is not None:
            groups.setdefault((fact["connector"], fact["source_id"]), []).append(fact)
    for group in groups.values():
        if len(group) < 2:
            continue
        id_path = group[0]["row"]["id"][0]
        refs = [fact["cite"].get(id_path) for fact in group]
        if len({fact["hash"] for fact in group}) > 1:
            out.append(finding("ID_COLLISION", refs))
        elif len({fact["identity"] for fact in group}) == 1:
            out.append(finding("DUPLICATE_DELIVERY", refs))

    for a, b in combinations(ctx["events"], 2):
        if a["connector"] != b["connector"] or a["thread"] is None or b["thread"] is None:
            continue
        if a["source_id"] is not None and a["source_id"] == b["source_id"]:
            continue  # same ID is the duplicate rule's job
        parent, child = sorted((a, b), key=lambda fact: len(fact["thread"][1]))
        if (parent["thread"][0] != child["thread"][0] or len(parent["thread"][1]) == len(child["thread"][1])
                or not child["thread"][1].startswith(parent["thread"][1])):
            continue
        thread = parent["row"]["thread"]
        out.append(finding("THREAD_RELATION_ASSERTED", [fact["cite"].get(path) for fact in (parent, child)
                                                        for path in (thread["id"], thread["index"], parent["row"]["id"][0])]))
        new_text, full_text = child["norm"].get(thread["new_text"]), parent["norm"].get(thread["full_text"])
        if new_text is None or full_text is None or " ".join(new_text.split()) not in " ".join(full_text.split()):
            out.append(finding("NEW_INFORMATION", [child["cite"].get(thread["new_text"])]))
    return out


def check_correlation(ctx):
    """Events from different connectors within 30 minutes of each other (in UTC) may be linked, never merged (AIR-07).

    Time window only; no keyword matching. This pack has no shared cross-connector identifier, so a
    pair is never proven. Skipped when either event time is missing.
    """
    out = []
    for a, b in combinations(ctx["events"], 2):
        if (a["connector"] != b["connector"] and a["time"] and b["time"]
                and abs(a["time"] - b["time"]) <= CORRELATION_WINDOW):
            out.append(finding("UNPROVEN_CORRELATION", [a["cite"].get(a["row"]["time"][0]), b["cite"].get(b["row"]["time"][0])]))
    return out


GATE_CHECKS = (check_envelope, check_provenance)
CONTENT_CHECKS = (check_injection, check_stale_state, check_duplicates, check_correlation)

# ---------------------------------------------------------------------------
# 4. combine, 5. final_guard, 6. decide
# ---------------------------------------------------------------------------


def combine(ctx, findings, analysed):
    """Build the output record from the findings.

    The disposition is the strictest minimum any finding sets (ACCEPT if none); nothing lowers it.
    Actions are the base action for the disposition plus those findings add, in priority order.
    QUARANTINE keeps only its own action; ACCEPT drops "draft incident" when the incident already
    exists (keep_incident_open was added).
    """
    codes = sorted({item["code"] for item in findings})
    disposition = max((REASONS[code][0] for code in codes), key=DISPOSITIONS.index, default="ACCEPT")
    if disposition == "QUARANTINE":
        actions = {BASE_ACTION["QUARANTINE"]}
    else:
        actions = {BASE_ACTION[disposition]}.union(*(item["actions"] for item in findings))
        if disposition == "ACCEPT" and "keep_incident_open" in actions:
            actions.discard("draft_incident_for_oncall")
    actions = [action for action in ACTIONS if action in actions]  # only listed actions survive, in priority order

    refs = {ref for item in findings for ref in item["refs"]}
    for fact in ctx["events"]:
        paths = ["provenance.verified"]
        if fact["row"] is not None:
            paths += [fact["row"]["time"][0], fact["row"]["id"][0]]
            if analysed:  # content of an untrusted event is not analysed, so not cited either
                paths += list(fact["row"]["free_text"])
        refs.update(fact["cite"][path] for path in paths if path in fact["cite"])

    state = ctx.get("observed_state")
    return {
        "case_id": ctx["case_id"],
        "disposition": disposition,
        "reason_codes": codes,
        "evidence_refs": [{"ref": ref, "kind": kind} for ref, kind in sorted(refs)],
        "safe_next_action": actions[0],
        "additional_actions": actions[1:],
        "human_review_required": disposition != "ACCEPT" or "STALE_STATE_IGNORED" in codes,
        "redaction_requirements": ctx["redactions"],
        "notes_on_uncertainty": [REASONS[code][2] for code in codes],
        "observed_state": state,
        "summary": summarise(ctx, disposition, state, analysed),
    }


def summarise(ctx, disposition, state, analysed):
    """A template sentence built only from typed facts and glossary wording, never from event text."""
    connectors = sorted({fact["connector"] for fact in ctx["events"] if fact["connector"]}) or ["unknown"]
    sentence = f"{disposition} for {len(ctx['events'])} event(s) from {', '.join(connectors)}."
    terms = {term for fact in ctx["events"] for term in fact["terms"]} if analysed else set()
    if terms:
        sentence += " Reported: " + ", ".join(wording for term, wording in GLOSSARY if term in terms) + "."
    if state is not None:
        sentence += f" Current state: {state}."
    return sentence


def one_of(words):
    """Regex alternation matching exactly one of `words`."""
    return "(?:" + "|".join(re.escape(word) for word in words) + ")"


_CONNECTOR_WORDS = (*CONNECTORS, "unknown")
_TERMS = one_of(wording for _, wording in GLOSSARY)
# The only summaries the guard lets through: the template above, filled from closed vocabularies.
SUMMARY = re.compile(
    rf"{one_of(DISPOSITIONS)} for [0-9]+ event\(s\) from {one_of(_CONNECTOR_WORDS)}(?:, {one_of(_CONNECTOR_WORDS)})*\."
    rf"(?: Reported: {_TERMS}(?:, {_TERMS})*\.)?"
    rf"(?: Current state: {one_of(JIRA_STATES + SNS_STATES)}\.)?")
MINIMAL_SUMMARY = "QUARANTINE; no detail is reported for this case."
REF = re.compile(r"e[0-9]{1,3}:[A-Za-z0-9_.#=\[\]-]+")


def minimal_record(case_id, code, redactions):
    """The fallback QUARANTINE record used for POLICY_ERROR and OUTPUT_GUARD_TRIPPED: constants only."""
    return {
        "case_id": case_id,
        "disposition": "QUARANTINE",
        "reason_codes": [code],
        "evidence_refs": [],
        "safe_next_action": BASE_ACTION["QUARANTINE"],
        "additional_actions": [],
        "human_review_required": True,
        "redaction_requirements": redactions,
        "notes_on_uncertainty": [REASONS[code][2]],
        "observed_state": None,
        "summary": MINIMAL_SUMMARY,
    }


def ref_ok(case, item, kinds):
    """True if a {ref, kind} item has a known kind and a well-formed ref that resolves to a non-null field."""
    return (set(item) == {"ref", "kind"} and item["kind"] in kinds and isinstance(item["ref"], str)
            and REF.fullmatch(item["ref"]) is not None and resolve_ref(case, item["ref"]) is not None)


def final_guard(case, record):
    """Re-check the finished record; if anything is off, replace it with a minimal QUARANTINE record.

    Every string must be a constant, a resolvable ref or a validated typed value; the disposition,
    actions and review flag must be what the reason codes imply; and no secret pattern may match the
    serialised record. The replacement keeps the valid redaction entries.
    """
    redaction_kinds = PII_KINDS | SECRET_KINDS
    codes = record.get("reason_codes")
    actions = [record.get("safe_next_action"), *record.get("additional_actions", [])]
    serialised = json.dumps(record, sort_keys=True)
    ok = (tuple(record) == OUTPUT_KEYS
          and (record["case_id"] == "UNKNOWN" or CASE_ID.fullmatch(record["case_id"]) is not None)
          and record["disposition"] in DISPOSITIONS
          and isinstance(codes, list) and all(code in REASONS for code in codes) and codes == sorted(set(codes))
          and record["notes_on_uncertainty"] == [REASONS[code][2] for code in codes]
          and all(action in ACTIONS for action in actions) and actions == sorted(set(actions), key=ACTIONS.index)
          # consistency: disposition, actions and review flag must be what the reason codes imply
          and record["disposition"] == max((REASONS[code][0] for code in codes), key=DISPOSITIONS.index, default="ACCEPT")
          and (record["disposition"] != "QUARANTINE" or actions == [BASE_ACTION["QUARANTINE"]])
          and record["human_review_required"] is (record["disposition"] != "ACCEPT" or "STALE_STATE_IGNORED" in codes)
          and record["observed_state"] in (None, *JIRA_STATES, *SNS_STATES)
          and isinstance(record["summary"], str) and SUMMARY.fullmatch(record["summary"]) is not None
          and all(ref_ok(case, item, ("observed", "asserted")) for item in record["evidence_refs"])
          and all(ref_ok(case, item, redaction_kinds) for item in record["redaction_requirements"])
          and not any(pattern.search(serialised) for _, pattern in SECRET_PATTERNS))
    if ok:
        return record
    kept = [item for item in record.get("redaction_requirements", []) if ref_ok(case, item, redaction_kinds)]
    return minimal_record(safe_case_id(case), "OUTPUT_GUARD_TRIPPED", kept)


def run_check(check, ctx):
    """Run one check and log its name and reason codes (never values)."""
    found = check(ctx)
    log.debug("case=%s check=%s codes=%s", ctx["case_id"], check.__name__, ",".join(item["code"] for item in found))
    return found


def decide(case):
    """Decide one case. Never raises: any exception becomes a minimal QUARANTINE record with POLICY_ERROR.

    Logs only the case ID, check names, reason codes and exception type names. Never values or
    str(exception), because exception messages can echo input, including secrets.
    """
    case_id, redactions = safe_case_id(case), []
    try:
        ctx = extract(case)
        ctx["redactions"] = redactions = sanitize(ctx)
        findings = []
        for check in GATE_CHECKS:
            findings += run_check(check, ctx)
        # Gate: if the envelope or provenance quarantines, the content is not analysed at all.
        analysed = not any(REASONS[item["code"]][0] == "QUARANTINE" for item in findings)
        findings += run_check(check_sensitive, ctx)  # secrets are recorded even when quarantined
        if analysed:
            for check in CONTENT_CHECKS:
                findings += run_check(check, ctx)
        record = final_guard(case, combine(ctx, findings, analysed))
    except Exception as error:  # fail closed, but never hide it: tests treat POLICY_ERROR as a failure
        log.warning("case=%s policy_error=%s", case_id, type(error).__name__)
        return minimal_record(case_id, "POLICY_ERROR", redactions)  # keeps any redactions already found
    log.info("case=%s disposition=%s codes=%s", case_id, record["disposition"], ",".join(record["reason_codes"]))
    return record


def main(argv):
    """CLI: print one decision per line as JSON with sorted keys, ordered by case ID."""
    if len(argv) != 2:
        print("usage: python3 policy.py fixtures/events.jsonl", file=sys.stderr)
        return 2
    decisions = []
    with open(argv[1], encoding="utf-8", errors="replace") as lines:  # a bad byte must not stop the run
        for line in lines:
            if line.strip():
                try:
                    case = json.loads(line)
                except (ValueError, RecursionError):
                    case = None  # an unreadable line still gets a QUARANTINE decision
                decisions.append(decide(case))
    for decision in sorted(decisions, key=lambda item: item["case_id"]):  # stable: equal IDs keep file order
        print(json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

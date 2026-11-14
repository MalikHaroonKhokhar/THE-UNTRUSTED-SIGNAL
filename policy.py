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
#   state      where a state change (from -> to) is read, and the states it may take
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
        "attested": ("payload.body.timestamp", "payload.body.changelog"),
        "state": {"items": "payload.body.changelog.items", "refs": ("payload.body.changelog",), "known": JIRA_STATES},
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
    # scheme://user:password@ . Yes: postgres://app:pw@db. No: https://host:5432/x (no "@").
    ("url_credentials", r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@"),
))
PII_PATTERNS = tuple((kind, re.compile(pattern)) for kind, pattern in (
    # local@domain.tld. Yes: farah@inbox-mail.example. No: farah@localhost (no dot-TLD).
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
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
                     r"\bto\s+<?[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
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


def locate(root, path):
    """Find where `path` points inside `root`: return (container, key), or None if a step is missing.

    Steps are separated by "." and take three forms:
      key          dict lookup
      key[name=X]  the first item named X (case-insensitive) in a list of {"name", "value"} items
      key#sub      parse the string at key as JSON, then look up sub
    List positions are not supported on purpose, so refs stay valid when items are reordered.
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


def safe_case_id(case):
    """The case ID if it has the expected shape, else "UNKNOWN". Only a safe ID is ever echoed or logged."""
    case_id = case.get("case_id") if isinstance(case, dict) else None
    return case_id if isinstance(case_id, str) and CASE_ID.fullmatch(case_id) else "UNKNOWN"


# ---------------------------------------------------------------------------
# Pipeline: extract -> sanitize -> checks -> combine -> final_guard. Not implemented yet.
# ---------------------------------------------------------------------------


def extract(case):
    """Turn the raw case into typed facts. This is the only function that reads raw payload values."""
    raise NotImplementedError


def sanitize(ctx):
    """Return every place a value must be masked, as a sorted list of {ref, kind}."""
    raise NotImplementedError


def check_envelope(ctx):
    """Malformed envelope, unknown connector, or a payload that cannot be parsed for its connector (AIR-08)."""
    raise NotImplementedError


def check_provenance(ctx):
    """Every provenance and timing defect of every event, not just the first (AIR-08 lists five)."""
    raise NotImplementedError


def check_sensitive(ctx):
    """PII_REDACTED and SECRET_SHAPED_VALUE from the redactions sanitize() recorded (AIR-05)."""
    raise NotImplementedError


def check_injection(ctx):
    """Instructions in free text are flagged, never followed (AIR-04). Detection only ever adds strictness."""
    raise NotImplementedError


def check_stale_state(ctx):
    """Work out the current state from event time, never arrival order (AIR-03, AIR-06)."""
    raise NotImplementedError


def check_duplicates(ctx):
    """Deduplicate only on proof (AIR-06), and only claim a thread relation for forwards (AIR-02)."""
    raise NotImplementedError


def check_correlation(ctx):
    """Events from different connectors within 30 minutes of each other (in UTC) may be linked, never merged (AIR-07)."""
    raise NotImplementedError


def combine(ctx, findings, analysed):
    """Build the output record from the findings."""
    raise NotImplementedError


def final_guard(case, record):
    """Re-check the finished record; if anything is off, replace it with a minimal QUARANTINE record."""
    raise NotImplementedError


GATE_CHECKS = (check_envelope, check_provenance)
CONTENT_CHECKS = (check_injection, check_stale_state, check_duplicates, check_correlation)
MINIMAL_SUMMARY = "QUARANTINE; no detail is reported for this case."


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
    case_id = safe_case_id(case)
    try:
        ctx = extract(case)
        ctx["redactions"] = sanitize(ctx)
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
        return minimal_record(case_id, "POLICY_ERROR", [])
    log.info("case=%s disposition=%s codes=%s", case_id, record["disposition"], ",".join(record["reason_codes"]))
    return record


def main(argv):
    """CLI: print one decision per line as JSON with sorted keys, ordered by case ID."""
    if len(argv) != 2:
        print("usage: python3 policy.py fixtures/events.jsonl", file=sys.stderr)
        return 2
    decisions = []
    with open(argv[1], encoding="utf-8") as lines:
        for line in lines:
            if line.strip():
                try:
                    case = json.loads(line)
                except ValueError:
                    case = None  # an unreadable line still gets a QUARANTINE decision
                decisions.append(decide(case))
    for decision in sorted(decisions, key=lambda item: item["case_id"]):  # stable: equal IDs keep file order
        print(json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

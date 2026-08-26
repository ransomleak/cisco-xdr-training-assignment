#!/usr/bin/env python3
"""Assign RansomLeak security awareness training to the people named in a Cisco XDR incident.

A SOC analyst working an incident already knows which employee clicked the link.
This closes the loop in one step: pull the `email` observables off the incident,
and assign each of them a short remedial lesson in RansomLeak.

Run it from an XDR Automation workflow (a pivot-menu trigger on an `email`
observable puts it in front of the analyst mid-investigation), from a SOAR
playbook, or straight from a terminal.

Usage:
    # from an incident payload
    python assign_training.py --incident-file incident.json

    # or a single address, e.g. from a pivot menu
    python assign_training.py --email jane@example.com --incident-id INC-1234

    # see what would happen, call nothing
    python assign_training.py --incident-file incident.json --dry-run

Exit codes:
    0  every assignment succeeded, or --dry-run
    1  configuration or input error, nothing was sent
    2  at least one assignment failed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Iterable

import requests

# Observable types Cisco XDR uses for a person. Both are valid values in the
# Enrich API's observable type enum; `user` may hold a bare username rather than
# an address, so it is only treated as an assignee when it looks like an email.
EMAIL_OBSERVABLE_TYPES = ("email", "user")

DEFAULT_TIMEOUT_SECONDS = 30

# `POST /assignments` rejects a callback URL that is not publicly routable. That
# case answers WEBHOOK_INVALID_URL today and becomes INTEGRATION_INVALID_CALLBACK
# on or after 2026-11-01; RansomLeak's own docs ask integrators to accept both, so
# both are matched here rather than only whichever is current.
INVALID_CALLBACK_CODES = ("WEBHOOK_INVALID_URL", "INTEGRATION_INVALID_CALLBACK")


class ConfigError(Exception):
    """Raised when the environment or arguments cannot produce a valid request."""


def require_env(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise ConfigError(
            f"{name} is not set. Copy .env.example, fill it in, and export it "
            f"(for example: set -a; . ./.env; set +a)."
        )
    return value


def looks_like_email(value: str) -> bool:
    """Cheap shape check. The API validates properly; this only decides whether a
    `user` observable is an address or a bare username we should skip."""
    return "@" in value and "." in value.split("@")[-1] and " " not in value


def iter_observables(incident: dict[str, Any]) -> Iterable[Any]:
    """Yield observable dicts from an incident payload.

    Two shapes are handled, and only two. A flat `observables` list is what a
    pivot-menu trigger and a webhook body carry. When a whole incident is
    delivered instead, its observables hang off the sightings that produced
    them, either directly or on one of a sighting's targets. Anything else is
    ignored rather than guessed at.
    """
    yield from incident.get("observables") or []

    for sighting in incident.get("sightings") or []:
        if not isinstance(sighting, dict):
            continue
        yield from sighting.get("observables") or []
        for target in sighting.get("targets") or []:
            if isinstance(target, dict):
                yield from target.get("observables") or []


def extract_emails(incident: dict[str, Any]) -> list[str]:
    """Collect assignee addresses from an XDR incident payload.

    Order is preserved and addresses are deduplicated case-insensitively, so a
    person named by several observables in one incident is assigned once.
    """
    found: list[str] = []
    seen: set[str] = set()

    for observable in iter_observables(incident):
        if not isinstance(observable, dict):
            continue
        if observable.get("type") not in EMAIL_OBSERVABLE_TYPES:
            continue

        value = str(observable.get("value") or "").strip()
        if not value or not looks_like_email(value):
            continue

        key = value.lower()
        if key not in seen:
            seen.add(key)
            found.append(value)

    return found


def build_payload(
    email: str,
    exercise_slug: str,
    incident_id: str,
    incident: dict[str, Any] | None,
    callback_url: str | None,
) -> dict[str, Any]:
    """One assignment request.

    `idempotencyKey` is derived from the incident, the person, and the lesson, so
    re-running the workflow on the same incident replays the original assignment
    instead of assigning the same lesson twice. That is the API's documented
    behaviour and it is what makes this safe to wire to an automatic trigger.
    """
    trigger_context: dict[str, Any] = {"incidentId": incident_id}
    if incident:
        if incident.get("title"):
            trigger_context["incidentTitle"] = incident["title"]
        if incident.get("severity"):
            trigger_context["severity"] = incident["severity"]

    payload: dict[str, Any] = {
        "user": {"email": email},
        "exerciseSlug": exercise_slug,
        "idempotencyKey": f"cisco-xdr:{incident_id}:{email.lower()}:{exercise_slug}",
        "source": "cisco-xdr",
        "reference": incident_id,
        "triggerContext": trigger_context,
    }
    if callback_url:
        payload["callbackUrl"] = callback_url
    return payload


def assign(session: requests.Session, base_url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST one assignment. `base_url` is expected to have no trailing slash."""
    response = session.post(
        f"{base_url}/api/integration/assignments",
        json=payload,
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    if response.ok:
        return response.json()

    raise RuntimeError(f"HTTP {response.status_code}: {describe_error(response)}")


def describe_error(response: requests.Response) -> str:
    """Turn an error response into something an analyst can act on."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:300] or "(empty response body)"

    code = body.get("code")
    message = body.get("message") or body.get("error") or json.dumps(body)[:300]

    if code in INVALID_CALLBACK_CODES:
        return (
            f"{message} — RANSOMLEAK_CALLBACK_URL must be reachable from the public internet. "
            f"Unset it if you do not need completion callbacks."
        )
    if response.status_code == 401:
        return f"{message} — check RANSOMLEAK_API_TOKEN and that it carries the 'integration' scope."
    if response.status_code == 404:
        return f"{message} — check RANSOMLEAK_EXERCISE_SLUG names a lesson in your catalog."
    return f"{message}{f' (code: {code})' if code else ''}"


def load_incident(path: str) -> dict[str, Any]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()

    try:
        incident = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"could not parse incident JSON: {exc}") from exc
    if not isinstance(incident, dict):
        raise ConfigError("incident JSON must be an object")
    return incident


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assign RansomLeak training to the people named in a Cisco XDR incident.",
        epilog="Configuration is read from the environment; see .env.example.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--incident-file", metavar="PATH", help="XDR incident JSON, or - for stdin")
    source.add_argument("--email", help="assign a single address directly")
    parser.add_argument(
        "--incident-id",
        help="incident reference used for idempotency; taken from the incident when not given",
    )
    parser.add_argument(
        "--exercise-slug",
        help="lesson to assign; defaults to RANSOMLEAK_EXERCISE_SLUG",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the requests, send nothing")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Only the two calls that can fail on bad input or environment live in here.
    # Note requests.RequestException subclasses OSError, so the send loop must
    # stay outside: inside, a network failure would report "Could not read
    # incident" and send an analyst looking at the wrong thing.
    try:
        incident: dict[str, Any] | None = None
        if args.incident_file:
            incident = load_incident(args.incident_file)
            emails = extract_emails(incident)
        else:
            emails = [args.email]

        base_url = require_env("RANSOMLEAK_BASE_URL").rstrip("/")
        exercise_slug = args.exercise_slug or require_env("RANSOMLEAK_EXERCISE_SLUG")
        # A dry run sends nothing, so it must not demand a token to work.
        token = None if args.dry_run else require_env("RANSOMLEAK_API_TOKEN")
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not read incident: {exc}", file=sys.stderr)
        return 1

    if not emails:
        print("No email observables on this incident, nothing to assign.", file=sys.stderr)
        return 0

    incident_id = str(args.incident_id or (incident or {}).get("id") or "manual")
    callback_url = (os.environ.get("RANSOMLEAK_CALLBACK_URL") or "").strip() or None
    payloads = [
        build_payload(email, exercise_slug, incident_id, incident, callback_url) for email in emails
    ]

    if args.dry_run:
        print(f"Would assign '{exercise_slug}' to {len(payloads)} person(s) via {base_url}:")
        for payload in payloads:
            print(json.dumps(payload, indent=2))
        return 0

    session = requests.Session()
    session.headers.update(
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    )

    failures = 0
    for payload in payloads:
        email = payload["user"]["email"]
        try:
            result = assign(session, base_url, payload)
        except (RuntimeError, requests.RequestException) as exc:
            failures += 1
            print(f"FAILED  {email}: {exc}", file=sys.stderr)
            continue

        print(f"OK      {email} -> {result.get('status', 'assigned')} ({result.get('assignmentId')})")
        deep_link = result.get("deepLink")
        if deep_link:
            print(f"        {deep_link}")

    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

# Assign security awareness training from a Cisco XDR incident

Close the loop between detection and training. When a Cisco XDR incident names an
employee — the person who clicked the link, submitted credentials, or ran the
attachment — this assigns them a short remedial lesson in
[RansomLeak](https://ransomleak.com) without the analyst leaving their
investigation.

It reads the `email` observables off an incident and creates one assignment per
person through RansomLeak's partner integration API, returning a deep link
straight to the lesson.

```
$ python assign_training.py --incident-file examples/incident.json
OK      jane.doe@example.com -> assigned (7c2c3d3e-1234-5678-9abc-1234567890ab)
        https://acme.ransomleak.com/a/eyJhbGciOi...
OK      sam.patel@example.com -> assigned (9f1b7a20-4321-8765-cba9-0987654321fe)
        https://acme.ransomleak.com/a/eyJhbGciOi...
```

## Why this exists

Security awareness training is usually scheduled annually and disconnected from
what actually happens on the network. The incident that proves someone needs
training is the one moment they will remember it. Assigning the lesson while the
incident is still open turns a detection into a teaching moment, and gives the
security team a record that they responded to the human side of the incident,
not just the technical one.

## Solution components

- **Cisco XDR** — incidents and their `email` / `user` observables
- **RansomLeak** — security awareness training platform; the partner integration
  API creates the assignment and issues the learner deep link
- **Python 3.9+** with [requests](https://pypi.org/project/requests/)

## Prerequisites

- A RansomLeak tenant. If you do not have one, the integrations overview is at
  [ransomleak.com/integrations](https://ransomleak.com/integrations/) and the team
  can set one up.
- A partner API token with the `integration` scope, created by a RansomLeak
  administrator under **Settings → Integrations → API**.
- The slug of the lesson you want to assign, from your RansomLeak catalog.

## Installation

```bash
git clone https://github.com/ransomleak/cisco-xdr-training-assignment.git
cd cisco-xdr-training-assignment
pip install -r requirements.txt
cp .env.example .env      # then fill it in
set -a; . ./.env; set +a
```

## Configuration

All configuration is environment variables. Nothing is stored in the repo.

| Variable | Required | Description |
|---|---|---|
| `RANSOMLEAK_BASE_URL` | yes | Your tenant URL, e.g. `https://acme.ransomleak.com` |
| `RANSOMLEAK_API_TOKEN` | yes | Partner API token with the `integration` scope |
| `RANSOMLEAK_EXERCISE_SLUG` | yes | Lesson to assign, e.g. `phishing-introduction` |
| `RANSOMLEAK_EMAIL_DOMAINS` | for `--incident-file` | Your own email domains, comma separated, e.g. `acme.com,acme.co.uk` |
| `RANSOMLEAK_CALLBACK_URL` | no | RansomLeak POSTs here when the lesson is completed |

`RANSOMLEAK_API_TOKEN` can assign training to anyone in your tenant. Store it the
way you store any other API credential.

`RANSOMLEAK_EMAIL_DOMAINS` is what separates your employees from everyone else on
an incident, so reading an incident requires it. An incident names attackers as
well as victims: a credential-phishing incident carries the spoofed sender as an
`email` observable right beside the person who clicked. Without the list, this
would mail a lesson link to attacker-controlled addresses, and on an automatic
trigger nobody would see it happen. `--email` skips the filter, because there you
have chosen the address yourself.

## Usage

Assign to everyone named in an incident:

```bash
python assign_training.py --incident-file examples/incident.json
```

Assign a single address, which is what a pivot-menu trigger on an `email`
observable gives you:

```bash
python assign_training.py --email jane.doe@example.com --incident-id INC-2049
```

Read the incident from stdin, for piping out of another tool:

```bash
cat examples/incident.json | python assign_training.py --incident-file -
```

See exactly what would be sent, without sending it:

```bash
python assign_training.py --incident-file examples/incident.json --dry-run
```

| Exit code | Meaning |
|---|---|
| `0` | Every assignment succeeded, or `--dry-run`, or the incident named nobody |
| `1` | Configuration or input error; nothing was sent |
| `2` | At least one assignment failed; the rest were still attempted |

### Running it from Cisco XDR Automation

Point a workflow at this script and it runs wherever your workflow runner
executes. The two triggers that fit:

- **Pivot menu** on an `email` or `user` observable, which puts "assign training"
  in front of the analyst mid-investigation and passes a single address.
- **Incident**, to assign automatically when an incident is created or reaches a
  severity you choose. Because assignments are idempotent (below), a workflow that
  fires more than once on the same incident is safe.

## Assignments are idempotent

The idempotency key is derived from the incident, the person, and the lesson:

```
cisco-xdr:<incident-id>:<email>:<exercise-slug>
```

Re-running on the same incident replays the original assignment and reissues its
deep link rather than assigning the same lesson twice. That is what makes this
safe to attach to an automatic trigger, and it means you can re-run after fixing a
configuration mistake without spamming your employees.

## What it does not do

- It does not create a user directory in XDR or publish employee data into Cisco.
  The only thing that leaves your XDR instance is the address being assigned.
- It does not set a verdict or disposition on an observable. A person is not an
  indicator of compromise.
- It reads `user` observables only when they contain an email address. A bare
  username cannot be matched to a learner, so those are skipped rather than
  guessed at.
- It never assigns training to an address outside `RANSOMLEAK_EMAIL_DOMAINS`, so
  senders, reporters and other third parties on an incident are left alone.

## Related resources

- [RansomLeak integrations](https://ransomleak.com/integrations/) — the full list,
  including Webex, Slack, Microsoft Teams, Okta, Splunk and Jira
- [Cisco XDR Automation](https://developer.cisco.com/docs/cisco-xdr/) — workflows,
  triggers, and the observable type reference
- [Contact RansomLeak](https://ransomleak.com/contact-us/) — for a tenant, an API
  token, or help wiring this into a workflow

## Catalog / source

This project is published to Cisco Code Exchange from
`github.com/ransomleak/cisco-xdr-training-assignment`. The source of truth is
mirrored from the RansomLeak monorepo (`integrations/cisco-xdr/`), so please
raise issues and pull requests against the GitHub repo rather than patching a
copy.

## License

BSD 3-Clause. See [LICENSE](./LICENSE).

## Disclaimer

Provided as sample code to demonstrate the integration. It is not a supported
Cisco product. Test it against a non-production RansomLeak tenant before wiring it
to an automatic trigger, and confirm the lesson you assign is proportionate to the
incident that triggered it.

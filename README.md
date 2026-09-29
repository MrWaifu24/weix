# weix: Windows Event ID Explainer

[![CI](https://github.com/MrWaifu24/weix/actions/workflows/ci.yml/badge.svg)](https://github.com/MrWaifu24/weix/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.23%2B-00ADD8?logo=go)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`weix` is a command-line utility that explains Windows Event IDs for SOC analysts. You give it an event ID and it tells you:

- what the event means and which log records it
- why it matters for security
- which fields to inspect
- how to investigate it
- common false positives
- the matching MITRE ATT&CK techniques
- a starting point for a detection rule

It's a triage aid for the moment an alert shows an unfamiliar event ID and you'd otherwise have to search for it.

It ships as a single static binary with the knowledge base embedded, so it works offline, including on air-gapped IR jump boxes.

```
$ weix 4769
4769  A Kerberos service ticket was requested
─────────────────────────────────────────────
  Log          Security
  Provider     Microsoft-Windows-Security-Auditing
  Category     credential-access
  Criticality  LOW
  ATT&CK       T1558.003  Steal or Forge Kerberos Tickets: Kerberoasting

WHAT IT MEANS
  A client requested a service ticket (TGS-REQ) for an SPN. Logged on domain
  controllers. Audit policy - Account Logon > Audit Kerberos Service Ticket Operations.

WHY IT MATTERS
  Kerberoasting requests service tickets for accounts with SPNs, usually with RC4
  encryption (0x17), so the ticket can be cracked offline for the service account's
  password. A single user requesting many service tickets in a short time is a strong
  signal.

KEY FIELDS
  ServiceName
      Requested service account/SPN owner - user accounts (not ending in $) are
      Kerberoasting targets.
  TicketEncryptionType
      0x17 (RC4) is the classic Kerberoasting signal in modern AES environments.
  ...

INVESTIGATION
  • Group by requesting account - many distinct ServiceName values with 0x17 in minutes
    suggests Kerberoasting.
  • Rotate passwords for targeted service accounts; move them to gMSA or long random
    passwords.
  • Consider a honey SPN account whose ticket requests always alert.

COMMON FALSE POSITIVES
  • Legacy applications that only support RC4.

DETECTION IDEA
  EventID=4769 AND TicketEncryptionType=0x17 AND ServiceName NOT ending in '$' AND
  ServiceName != krbtgt -> suspicious; >= 5 distinct ServiceName per requester in 10
  minutes -> alert.

RELATED
  4768   Security       A Kerberos authentication ticket (TGT) was requested
  4624   Security       An account was successfully logged on
```

## Features

- **78 curated, security-relevant events** from 10 log sources:
  - Security, System
  - PowerShell (Operational and classic)
  - Sysmon
  - Microsoft Defender
  - RDP (RemoteConnectionManager and LocalSessionManager)
  - Task Scheduler
  - WMI-Activity
- **Every entry answers the same questions:**
  - What it means, including the audit policy that has to be enabled to get it
  - Why an analyst should care
  - Which fields to inspect and what bad values look like
  - Investigation steps
  - Common false positives
  - Related events
- **MITRE ATT&CK mapping** with technique names. JSON output includes links to attack.mitre.org.
- **Lookup tables** for the values you run into during triage:
  - `logon-type`: what LogonType 3, 9 or 10 means and why it matters
  - `status`: NTSTATUS failure codes (`0xC000006A`...) and Kerberos failure codes (`0x18`...) from 4625, 4771 and 4776
- **Keyword search** over names, descriptions, fields and ATT&CK techniques: `weix search dcsync`, `weix search T1053`.
- **Multi-channel aware:** the same numeric ID can mean different things in different logs, and `--channel` narrows the results.
- **JSON output** (`--json`) for scripts, SOAR playbooks and enrichment pipelines.
- Colors when writing to a terminal, plain text when piped. Honours `NO_COLOR`.

## Install

With Go 1.23+:

```sh
go install github.com/MrWaifu24/weix@latest
```

Or download a prebuilt binary for Linux, macOS or Windows (amd64/arm64) from the [Releases](https://github.com/MrWaifu24/weix/releases) page.

Or build from source:

```sh
git clone https://github.com/MrWaifu24/weix && cd weix
go build -o weix .
```

## Usage

```sh
weix 4624                     # explain one event
weix 4625 4740 4771           # explain several at once
weix 1 --channel sysmon       # restrict to a log (security, sysmon, powershell, defender, rdp ...)
weix 4104 --json              # machine-readable output

weix search kerberoasting     # search by keyword, field or ATT&CK technique
weix search lsass dump        # all terms must match
weix list                     # everything in the knowledge base
weix list --category persistence
weix list --categories        # categories with counts

weix logon-type 10            # what does LogonType 10 mean?
weix status 0xC000006A        # why did this 4625 fail?
weix status 0x18              # Kerberos failure code from 4771
```

The exit code is `0` on success and `1` if any requested ID or code is not in the knowledge base, which makes it easy to use in scripts.

```
$ weix search kerberos
ID     LOG                  LEVEL    NAME
4768   Security             LOW      A Kerberos authentication ticket (TGT) was request…
4769   Security             LOW      A Kerberos service ticket was requested
4771   Security             MEDIUM   Kerberos pre-authentication failed
4738   Security             MEDIUM   A user account was changed
4776   Security             LOW      The computer attempted to validate the credentials…

5 event(s). Run `weix <id>` for details.

$ weix status 0xC000006A
0xC000006A  STATUS_WRONG_PASSWORD  (NTSTATUS - 4625 / 4776)
  User name is correct but the password is wrong.
  SOC note: The attacker knows a valid account name. Bursts indicate brute force.

$ weix logon-type 9
Logon type 9 - NewCredentials
  runas /netonly - local identity unchanged, new credentials used for outbound network
  connections.

  SOC note: With LogonProcessName 'seclogo' this is a known pass-the-hash indicator
  (e.g. Mimikatz sekurlsa::pth creates type 9 logons).
```

## Coverage

| Log | Events |
|-----|--------|
| Security | 1102, 4624, 4625, 4634, 4647, 4648, 4656, 4657, 4662, 4663, 4670, 4672, 4688, 4689, 4697, 4698–4702, 4719, 4720, 4722–4726, 4728, 4732, 4738, 4740, 4756, 4767, 4768, 4769, 4771, 4776, 4778, 4779, 4798, 4799, 4964, 5136, 5140, 5145, 5156 |
| System | 104, 6005, 6006, 6008, 7036, 7040, 7045 |
| PowerShell | 4103, 4104 (Operational), 400, 800 (Windows PowerShell) |
| Sysmon | 1, 3, 7, 8, 10, 11, 12, 13, 22 |
| Microsoft Defender | 1116, 1117, 5001, 5007 |
| RDP | 1149 (RemoteConnectionManager), 21, 24, 25 (LocalSessionManager) |
| Task Scheduler | 106, 141, 200 |
| WMI-Activity | 5861 |

These events are grouped into categories such as `authentication`, `credential-access`, `persistence`, `lateral-movement`, `defense-evasion` and `log-tampering`. Use `weix list --categories` to see them all.

## How it works

```
data/
  events/*.yaml        curated knowledge base, one file per log family
  logon_types.yaml     LogonType lookup table
  status_codes.yaml    NTSTATUS + Kerberos failure codes
  mitre.yaml           ATT&CK technique names
internal/events/       loading, indexing (by ID + channel), search, lookups
internal/render/       terminal and JSON renderers
cmd/                   cobra CLI
```

- The YAML knowledge base is compiled into the binary with `go:embed`, so there are no runtime files to deploy.
- Events are indexed by `(id, channel)`, which keeps collisions such as Sysmon `1` vs. other providers unambiguous.
- Search ranks matches in the event name above matches on ID, category or ATT&CK technique, and those above matches in the body text.

The data is guarded by tests. `TestDatasetIntegrity` checks that:

- every entry has all required sections
- criticality and channel values are valid
- ATT&CK IDs are well formed and have names
- every "related" event exists in the knowledge base
- no `(id, channel)` pair is duplicated

## Adding an event

Add an entry to the right file in `data/events/`:

```yaml
- id: 4624
  channel: Security
  provider: Microsoft-Windows-Security-Auditing
  name: An account was successfully logged on
  category: authentication
  criticality: low            # info | low | medium | high
  description: >
    What the event records and which audit policy produces it.
  relevance: >
    Why a SOC analyst should care.
  mitre: [T1078, T1021]
  fields:
    - name: LogonType
      note: What to look for in this field.
  investigate:
    - Concrete investigation step.
  false_positives:
    - Common benign cause.
  related: [4625, 4634]
  detection: Optional pseudo-rule.
```

Then run `go test ./...`. The integrity tests will point out anything that's missing.

## Roadmap

- Sigma rule references for each event
- More Sysmon IDs (15, 17/18 named pipes, 19–21 WMI, 23/26 file delete)
- AD CS events (4886, 4887) and Kerberos delegation abuse
- `weix fields <id>` to show the XML field layout of an event

## References

- Microsoft Learn: [Advanced security audit policy events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- JPCERT/CC: *Detecting Lateral Movement through Tracking Event Logs*

## License

[MIT](LICENSE)

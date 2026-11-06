# CyberSecElite detections

Detection engineering by **Diyorbek Juraev** ([CyberSecElite](https://cybersecelite.com)).
This repository holds Splunk searches, hunts, offline tests and the research behind them,
focused on vulnerabilities that are being exploited in the wild.

| Pack | Covers | Version | Status |
|---|---|---|---|
| [php2shell](php2shell/) | PHP runtime RCE: CVE-2026-109618 and CVE-2026-109619 (CISA KEV, added 2026-10-26) | 1.0 (2026-11-06) | Experimental |

## Conventions

- **Status.** *Experimental* means the logic passes offline tests and every claim has
  been checked against primary sources, but the searches have not yet been run in a
  Splunk instance. *Production* means they have been run there and tuned.
- **Every claim is sourced.** Each pack links the vendor advisory, the CVE and KEV
  record, and any vendor or source-code evidence for the log strings it relies on.
- **Tests read the shipped files.** Each pack's offline test pulls its regexes straight
  from the `.spl` files and the README's copy-paste Splunk tests, so they cannot drift
  apart unnoticed.
- **How packs are prepared.** Drafts are written with AI assistance, then verified by
  the author against the cited sources before release. Each pack's README says what was
  and was not validated.

## Reporting issues

Open an issue with the pack name, your Splunk version, and (redacted) sample events.
Field results from real environments are especially welcome.

## License

[Apache License 2.0](LICENSE).

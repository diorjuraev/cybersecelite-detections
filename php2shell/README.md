# PHP2Shell Splunk detection pack

**Author:** Diyorbek Juraev · **Publisher:** CyberSecElite, LLC ([cybersecelite.com](https://cybersecelite.com))  
**Version:** 1.0 · **Published:** 2026-11-06 · **Status:** Experimental  
**Also published at:** [cybersecelite.com/intelligence/use-cases/php2shell-php-runtime-rce](https://cybersecelite.com/intelligence/use-cases/php2shell-php-runtime-rce/)  
**Covers:** CVE-2026-109618 (primary), CVE-2026-109619 (shared OOM trigger), and generic
PHP web-worker post-exploitation  
**Background research:** [RESEARCH.md](RESEARCH.md)

> **Validation status.** All three search regexes and the shell classifier pass an offline
> regression check, [`tests/check_regex.pl`](tests/check_regex.pl): 24 checks, run with
> Perl's PCRE-compatible engine against real PHP, Apache and PHP-FPM log formats. The
> check was mutation-tested, and four deliberate breakages are all caught. Claims about
> what PHP logs were checked against php-src at the release tags. The searches have
> **not** yet been run in a Splunk instance, which is why the status is "Experimental".
> Run the `makeresults` tests below before scheduling anything.
>
> **How this was prepared.** The first draft was written with AI assistance. Every factual
> claim was then re-checked against the primary sources linked here and the PHP source
> code. Report problems or field results to the author.

## The vulnerabilities

PHP2Shell is the name used for two critical PHP runtime vulnerabilities disclosed on
2026-10-21:

| CVE | Upstream title | What goes wrong |
|---|---|---|
| **CVE-2026-109618** ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) | RCE via OOM corruption | An out-of-memory `longjmp()` leaves request state partly initialized; shutdown treats it as valid. |
| **CVE-2026-109619** ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) | RCE via stale global state | Request-owned state outlives its freed memory and is consumed by a later request on the same worker. |

Both are rated Critical, CVSS v4.0 9.2 (`AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`), and are
fixed in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**
([PHP advisory](https://www.php.net/archive/2026.php)). PHP says updating is the only
complete fix.

**Known exploited.** CISA added both CVEs to the
[KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) on 2026-10-26,
with a federal due date of 2026-10-29. This was checked against the KEV JSON feed, catalog
version 2026.11.04.

**Why one log line covers both CVEs.** The upstream advisories name out-of-memory during
request input processing as the confirmed trigger that needs no application code. It is
the direct primitive for CVE-2026-109618. It is also the demonstrated "producer" step for
the CVE-2026-109619 session-upload-progress path, which was validated against `mod_php`
and FPM.

**Related, not covered: CVE-2026-115560.** This is a session-serializer issue (PHP notice
2026-10-23). As of PHP's 2026-11-05 news entry there is no fixed release. The interim
mitigation is `session.upload_progress.enabled=0`. Nothing in this pack targets it.

## What PHP's source code says about the log line

CrowdStrike's
[PHP2Shell post](https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/)
names `Allowed memory size … exhausted` together with `in Unknown on line 0` as its
request-startup signal. PHP writes "Unknown" and line 0 when no script is executing
(`main/main.c`). The log strings and the request-startup path were compared at the last
vulnerable tag and the fixed tag on every supported branch:
8.2.34→35, 8.3.35→36, 8.4.26→27 and 8.5.11→12. The results were the same on all four:

| Message (from `Zend/zend_alloc.c`) | Vulnerable builds | Fixed builds | What a hit means |
|---|---|---|---|
| `Allowed memory size of N bytes exhausted (tried to allocate M bytes)` | yes | **yes** | The memory limit was hit. Before the fix, PHP aborts at once. After it, the error is deferred and then raised again during request startup by `main/SAPI.c` (`zend_handle_delayed_oom`). That logs **the same line, still `in Unknown on line 0`**. |
| `Out of memory (allocated N bytes) (tried to allocate M bytes)` | yes | **no** | The system allocator failed. This is the path still exposed on hosts that applied PHP's `memory_limit=-1` stopgap. It appears **only on vulnerable builds**. |
| `Hard memory limit of N bytes exhausted (tried to allocate M bytes) in F on line L` | no | **yes** | This is new in the fix. It is written to stderr, then `_exit(137)`. It appears **only on fixed builds**. |

What this means in practice:

1. **The primary alert measures attack attempts, not exposure.** A patched host that gets
   the same multipart flood logs the same line. Use PHP version inventory to tell a
   blocked attempt from a live risk. Do not read a quiet patched fleet as "the alert is
   broken".
2. **The `memory_limit=-1` stopgap changes the message.** A detection that only matches
   `Allowed memory size` goes blind on exactly the hosts that could not patch. The primary
   search here also matches the unpatched-only `Out of memory (allocated …)` form, and
   tags it `oom_kind=system_allocation_unpatched_only`.
3. **Fixed builds have their own message.** `Hard memory limit … exhausted` means the
   runtime is patched and a worker was killed at the hard limit. On FPM, the master also
   logs `[pool …] child N exited with code 137` (`sapi/fpm/fpm/fpm_children.c`). That line
   is there even when worker stderr is not captured.

Distribution packages that backport the fix should carry the same strings, but check a
vendor build before relying on that.

## Artifacts

| File | Type | Severity / risk | What it finds |
|---|---|---|---|
| [`cse-det-php2shell-request-startup-oom-splunk-v1.spl`](cse-det-php2shell-request-startup-oom-splunk-v1.spl) | Scheduled alert | High / 80 on `dest` | Request-startup OOM fatal, both the memory-limit and the unpatched-only system-allocation forms. |
| [`cse-hunt-php2shell-web-worker-child-shell-splunk-v1.spl`](cse-hunt-php2shell-web-worker-child-shell-splunk-v1.spl) | Hunt / companion alert | High / 70 on `dest` | A PHP or web-server worker spawning a command shell (CIM `Endpoint.Processes`). |
| [`cse-hunt-php2shell-patched-hard-limit-splunk-v1.spl`](cse-hunt-php2shell-patched-hard-limit-splunk-v1.spl) | Hunt | Medium / 40 on `dest` | A patched runtime killing a worker at the hard memory limit (attempt against a fixed host, or memory DoS). |
| [`tests/check_regex.pl`](tests/check_regex.pl) | Offline test | — | Pulls each regex from the `.spl` files and checks it against fixtures. Run with `perl tests/check_regex.pl`. |

## Primary alert setup

The log searches start with the macro `` `php2shell_php_runtime_logs` ``. Define it as a
narrow selector for the indexes and sourcetypes that hold PHP, PHP-FPM, Apache `mod_php`,
LSAPI, FrankenPHP, or service-manager stderr logs. For example, adapt this to your local
names:

```spl
(index=web_runtime sourcetype IN ("apache:error", "php:error", "php:fpm:error"))
```

Do not deploy a scheduled `index=*` version. Before enabling the alert, confirm that a
known PHP memory-limit error is searchable and stays in one event after line breaking.

Recommended saved-search settings:

- Schedule: `*/5 * * * *`
- Earliest: `-10m@m`
- Latest: `-5m@m`
- Trigger: more than 0 results
- Severity / risk: High / 80 on `dest`. Raise it when `oom_kind` contains
  `system_allocation_unpatched_only`, or when inventory shows a vulnerable PHP build.
- Suppression: 15 minutes on `dest,source`, or `dest,site` when the virtual host is
  reliable
- ATT&CK: T1190, Exploit Public-Facing Application

The window does not overlap the previous run and leaves five minutes for ingestion. Change
it only after measuring the actual delay of the PHP error-log source.

### Primary false positives

- Legitimate oversized or malformed uploads that exhaust PHP before a script runs.
- Authorized load, fuzz or resilience tests.
- A low PHP `memory_limit` combined with normal request parsing.
- Startup modules or configuration that fail before the target script begins.
- Patched hosts receiving attack traffic. This is a true attempt but not an exposure;
  see above.

Treat a single match as a possible exploit primitive, not proof that RCE succeeded. Tune
the risk score, known test sources and maintenance windows locally. Do not allowlist an
entire upload route.

### Primary limitations

The alert will miss activity in these cases:

- PHP errors are not indexed, or error logging is disabled.
- Multiline parsing splits the message.
- The exploit path never produces the matched OOM message.

It is strongest for CVE-2026-109618. For CVE-2026-109619 it covers the OOM producer only,
not the other demonstrated producers (fatal and parse errors, timeouts, pre-initialization
diagnostics). A clean result is not evidence that an installation is safe.

## Endpoint companion setup

The companion needs process-creation telemetry mapped to the Splunk CIM
[`Endpoint.Processes`](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.4/data-models/endpoint)
data model, including parent process, process name, command line, user and destination.
It extends Splunk's own
[Web or Application Server Spawning a Shell](https://research.splunk.com/endpoint/8fdb41ad-091c-4d7a-af1d-9123fe94b539/)
idea to the PHP SAPIs: `php-fpm*`, `php-cgi*`, `lsphp*`, `frankenphp*`, Apache, and IIS
`w3wp.exe`.

Recommended settings:

- Schedule and window: the same five-minute schedule and `-10m@m` to `-5m@m` window.
- Trigger: more than 0 results.
- Severity / risk: High / 70 on `dest` for the standalone hunt.
- Suppression: 15 minutes on `dest,parent_process_name,process_name`.
- Correlation: promote to Critical / 95 when this signal and the primary alert, or a
  PHP2Shell WAF signal, hit the same `dest` within 10 minutes.

If `process_exec` or `original_file_name` is not accelerated in your data model, remove
them from the `tstats BY` clause and fall back to `process_name`. Check the mapped fields
before scheduling:

```spl
| datamodel Endpoint Processes search
| head 20
```

### Companion false positives

On Unix, PHP's `exec()`, `system()`, `shell_exec()`, `passthru()` and `popen()` all run
through `/bin/sh`, and so does `mail()`, which `popen()`s the sendmail command
(`ext/standard/mail.c`). Any PHP application that sends mail with `mail()` will therefore
produce `php-fpm → sh` on every message. Image converters, PDF renderers, deploy hooks and
cron wrappers do the same. Tune only on an exact approved parent, child, normalized
command line and owner-approved purpose (for example
`sh -c /usr/sbin/sendmail -t -i`). Never allowlist `sh` as a child on its own.

### Companion limitations

The companion is blind to:

- direct syscalls and in-process payloads
- renamed binaries that have no `original_file_name`
- hosts without EDR coverage

It flags a likely RCE outcome. It does not say which CVE or request caused it.

## Patched-runtime hard-limit hunt

`cse-hunt-php2shell-patched-hard-limit-splunk-v1.spl` uses the same macro. The message
reaches the log by one of two routes. Apache `mod_php` writes stderr to the `ErrorLog`.
FPM forwards it only when the pool sets `catch_workers_output = yes`. If FPM is not
capturing worker stderr, hunt the master's exit line instead:

```spl
`php2shell_php_runtime_logs` "exited with code 137"
| rex "\[pool\s+(?<fpm_pool>[^\]]+)\]\s+child\s+(?<fpm_child_pid>[0-9]+)\s+exited\s+with\s+code\s+137\b"
| where isnotnull(fpm_child_pid)
| stats count min(_time) AS firstTime max(_time) AS lastTime BY host fpm_pool
```

`request_startup=yes` (`in Unknown on line 0`) points at the input-parsing path the
exploit uses. A script path points at an application-level memory blow-up.

## Synthetic tests (run in Splunk Search)

Keep the `rex` and `eval` lines in these tests identical to the `.spl` files.

**Primary.** Expected: cases 1, 4 and 6 are `MATCH` (case 4 is the unpatched-only form);
cases 2, 3 and 5 are `NO_MATCH`.

```spl
| makeresults count=6
| streamstats count AS case_id
| eval _raw=case(
    case_id=1, "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
    case_id=2, "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in /var/www/html/index.php on line 42",
    case_id=3, "PHP Warning:  Unknown: Input variables exceeded 1000. in Unknown on line 0",
    case_id=4, "PHP Fatal error:  Out of memory (allocated 2097152 bytes) (tried to allocate 1073741824 bytes) in Unknown on line 0",
    case_id=5, "Hard memory limit of 201326592 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
    case_id=6, "[php:error] [pid 9] PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0, referer: https://example.test/upload")
| rex field=_raw "(?is)\b(?:allowed\s+memory\s+size\s+of\s+(?<php_memory_limit_bytes>[0-9]+)\s+bytes\s+exhausted|out\s+of\s+memory\s+\(\s*allocated\s+(?<php_allocated_bytes>[0-9]+)\s+bytes\s*\))(?:\s+at\s+\S+:[0-9]+)?(?:\s*\(\s*tried\s+to\s+allocate\s+(?<php_attempted_allocation_bytes>[0-9]+)\s+bytes\s*\))?\s+in\s+Unknown\s+on\s+line\s+0\b"
| eval result=if(isnotnull(php_memory_limit_bytes) OR isnotnull(php_allocated_bytes), "MATCH", "NO_MATCH")
| table case_id result php_memory_limit_bytes php_allocated_bytes php_attempted_allocation_bytes _raw
```

**Companion classification.** The `tstats` stage needs real telemetry, but the shell
classification after it can be checked on its own. Expected: cases 1, 2, 5 and 6 are
`MATCH` (T1059.004, T1059.003, T1059.001, T1059.001); cases 3 and 4 are `NO_MATCH`.
Case 6 is a renamed PowerShell, caught by `original_file_name`.

```spl
| makeresults count=6
| streamstats count AS case_id
| eval original_file_name=case(case_id=1, "bash", case_id=6, "PowerShell.EXE", 1=1, "unknown")
| eval process_exec=case(case_id=1, "/usr/bin/bash", case_id=2, "C:\\Windows\\System32\\cmd.exe", case_id=3, "/usr/bin/convert", case_id=4, "/usr/bin/php8.3", 1=1, "unknown")
| eval process_name=case(case_id=1, "bash", case_id=2, "cmd.exe", case_id=3, "convert", case_id=4, "php8.3", case_id=5, "pwsh", case_id=6, "svchost.exe")
| eval original_l=replace(lower(original_file_name), "^.*[/\\\\]", ""), exec_l=replace(lower(process_exec), "^.*[/\\\\]", ""), name_l=replace(lower(process_name), "^.*[/\\\\]", "")
| eval child_l=case(match(original_l, "^((sh|bash|dash|ash|zsh|ksh|busybox|cmd|powershell|pwsh)([.]exe)?|wscript[.]exe|cscript[.]exe)$"), original_l, match(exec_l, "^((sh|bash|dash|ash|zsh|ksh|busybox|cmd|powershell|pwsh)([.]exe)?|wscript[.]exe|cscript[.]exe)$"), exec_l, match(name_l, "^((sh|bash|dash|ash|zsh|ksh|busybox|cmd|powershell|pwsh)([.]exe)?|wscript[.]exe|cscript[.]exe)$"), name_l)
| eval mitre_attack=case(in(child_l, "powershell", "powershell.exe", "pwsh", "pwsh.exe"), "T1059.001", in(child_l, "cmd", "cmd.exe"), "T1059.003", isnotnull(child_l), "T1059.004")
| eval result=if(isnotnull(child_l), "MATCH", "NO_MATCH")
| table case_id result child_l mitre_attack original_file_name process_exec process_name
```

**Hard limit.** Expected: case 1 is `MATCH` with `request_startup=yes`; case 2 is `MATCH`
with `request_startup=no`; case 3 is `NO_MATCH`.

```spl
| makeresults count=3
| streamstats count AS case_id
| eval _raw=case(
    case_id=1, "Hard memory limit of 201326592 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0",
    case_id=2, "Hard memory limit of 201326592 bytes exhausted (tried to allocate 8192 bytes) in /var/www/html/import.php on line 88",
    case_id=3, "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0")
| rex field=_raw "(?is)\bhard\s+memory\s+limit\s+of\s+(?<php_hard_limit_bytes>[0-9]+)\s+bytes\s+exhausted(?:\s+at\s+\S+:[0-9]+)?\s*\(\s*tried\s+to\s+allocate\s+(?<php_attempted_allocation_bytes>[0-9]+)\s+bytes\s*\)\s+in\s+(?<php_error_file>.+?)\s+on\s+line\s+(?<php_error_line>[0-9]+)"
| eval request_startup=if(lower(php_error_file)="unknown" AND php_error_line="0", "yes", "no")
| eval result=if(isnotnull(php_hard_limit_bytes), "MATCH", "NO_MATCH")
| table case_id result request_startup php_hard_limit_bytes php_error_file php_error_line _raw
```

## Optional WAF and network correlation

If Cloudflare WAF events are indexed, correlate the current PHP2Shell managed-rule IDs
with the signals above. Cloudflare publishes the IDs, and says its newer detection looks
at the request and the origin response together, because the request alone is not
enough for some paths. Take the current list from Cloudflare instead of freezing it into
a local rule: see the
[PHP2Shell WAF post](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) and
the [WAF changelog](https://developers.cloudflare.com/waf/change-log/changelog/).
The rule IDs and Corelight's Zeek and Suricata signatures, as of 2026-10-21, are listed in
[RESEARCH.md](RESEARCH.md) §5–6.

Keep multipart traits as hunts, not alerts: upload-progress fields, large bodies, missing
`Content-Length`, many parts. None is malicious by itself, and the upload-progress field
name is configurable.

## Triage after a match

1. Before restarting or reimaging, preserve the PHP and web-server error logs, access
   logs, and WAF, process, network and file telemetry around the event.
2. Check the PHP build on `dest` against 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, or the
   vendor backport. A patched host turns an alert into a blocked attempt.
3. Correlate source, virtual host, path, request ID and time with large or malformed
   multipart requests and any WAF event.
4. Review child processes, outbound connections, file writes, new PHP files, service
   changes and credential access on the destination.
5. If process execution or memory disclosure is suspected, isolate the host and rotate
   any secrets the PHP worker can read.
6. Update every PHP runtime to a fixed or vendor-backported build, and restart every
   long-running worker. Updating the application or CMS alone is not enough.

## Sources

- PHP project: [2026 news archive and advisory](https://www.php.net/archive/2026.php) ·
  [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) ·
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- PHP source compared at tags `php-8.{2.34,2.35,3.35,3.36,4.26,4.27,5.11,5.12}`:
  `Zend/zend_alloc.c`, `main/SAPI.c`, `main/main.c`, `sapi/fpm/fpm/fpm_children.c`,
  `ext/standard/mail.c` ([php/php-src](https://github.com/php/php-src))
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CrowdStrike: PHP RCE zero-days](https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/)
- [Cloudflare: PHP2Shell WAF protection](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [Splunk Security Content: Web or Application Server Spawning a Shell](https://research.splunk.com/endpoint/8fdb41ad-091c-4d7a-af1d-9123fe94b539/)
- [Wiz Research: PHP2Shell disclosure](https://www.wiz.io/blog/php2shell-php-rce) ·
  [Corelight php2shell-detect (Zeek/Suricata)](https://github.com/corelight/php2shell-detect).
  More sources are listed in [RESEARCH.md](RESEARCH.md).

# PHP2Shell — primary-source research for Splunk detection

**Author:** Diyorbek Juraev, CyberSecElite · **First written:** 2026-10-21 · **Re-verified:** 2026-11-06
**Purpose:** Background research behind the Splunk detection pack in [README.md](README.md).
**Access date for every source in the body:** 2026-10-21.
**How this was prepared:** The first draft was written with AI assistance. Every factual
claim was then re-checked against the primary sources cited inline, and the log-message
claims were checked against PHP's own source code at the release tags (see README.md,
"What PHP's source code says").

---

> **Addendum 2026-11-06 (developments after the first draft, all verified):**
>
> - **Exploited in the wild.** CISA added both CVEs to the Known Exploited Vulnerabilities
>   catalog on 2026-10-26 (federal due date 2026-10-29). Checked against the CISA KEV JSON
>   feed, catalog version 2026.11.04. That goes beyond the attack attempts described in §1.
> - **Patched runtimes still log the OOM line.** PHP's source at the fixed tags shows
>   that the patch defers the memory-limit error and raises it again during request startup.
>   The message is the same `Allowed memory size … in Unknown on line 0`. An OOM-based
>   detection therefore measures attack attempts on every host, patched or not. Telling
>   the two apart takes version inventory. Details and the unpatched-only and patched-only
>   message variants are in README.md.
> - **Related, out of scope: CVE-2026-115560.** This is a session-serializer issue (PHP
>   notice 2026-10-23). As of PHP's 2026-11-05 news entry there is no fixed release. PHP's
>   interim mitigation is `session.upload_progress.enabled=0`. Nothing in this pack targets it.
> - **Corrections to the body.** Re-checking the sources on 2026-11-06 led to two changes
>   in §5–6. Corelight has since added a fourth Suricata rule, SID 3000653. The first draft
>   also listed a Cloudflare "Response Firewall" rule ID that Cloudflare's post does not
>   contain, and that ID has been removed. Every other Cloudflare ID and every Corelight
>   SID and notice type was confirmed against the live post, rules file and Zeek scripts.
>
> Apart from those two marked corrections, the body below is the 2026-10-21 snapshot.

## 1. Executive answer

As of 2026-10-21, “the latest PHP2Shell vulnerability” most likely means **two newly disclosed core-PHP vulnerabilities, not one**:

- **CVE-2026-109618 / GHSA-w8hw-w9fx-j79w — “RCE via OOM corruption.”**
- **CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp — “RCE via stale global state.”**

The PHP project published both advisories and fixed releases on 2026-10-21. Each advisory is Critical, CVSS v4.0 **9.2**, network reachable, unauthenticated, and capable of remote code execution with the PHP web-worker account’s privileges. The canonical upstream names are the two CVE/GHSA pairs; “PHP2Shell” is the discoverer/vendor umbrella label, not either upstream advisory title. ([PHP release advisory](https://www.php.net/archive/2026.php), [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce), [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))

This identification is **high confidence**. Cloudflare reports attack traffic targeting customers and attackers mutating payloads before public disclosure. That confirms active attempts, but its post does not claim those attempts produced confirmed compromises. Detection should distinguish `attempt`, `possible success`, and `confirmed post-exploitation`. ([Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))

## 2. Canonical identity and affected versions

| Canonical item | Upstream description | Fixed supported releases |
|---|---|---|
| **CVE-2026-109618** / **GHSA-w8hw-w9fx-j79w** | OOM handling can leave partially initialized request state that shutdown later treats as valid, enabling memory corruption and RCE. | **8.2.35, 8.3.36, 8.4.27, 8.5.12**. ([Upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) |
| **CVE-2026-109619** / **GHSA-6wmf-4rv5-p3rp** | Request-owned state can remain after its memory is freed; a later request handled by that worker can consume stale state, causing use-after-free, memory disclosure, and RCE. | **8.2.35, 8.3.36, 8.4.27, 8.5.12**. ([Upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) |

The PHP project says all PHP installations serving web requests are at risk, including PHP-FPM, Apache `mod_php`, `php-cgi`, FrankenPHP, and LiteSpeed. It considers demonstrated risk highest for `mod_php`, where an unauthenticated request can trigger the attack before application code runs. ([PHP release advisory](https://www.php.net/archive/2026.php))

PHP 8.1 and older no longer receive normal PHP-project releases. The project published minimal source backports for 7.4, 8.0, and 8.1 and directs distribution/LTS users to their package vendor. Wiz Research and Cloudflare state that at least one PHP2Shell flaw reaches back to PHP 5.4. Do not judge a vendor package only by its apparent upstream version; check its backport status. ([PHP release advisory](https://www.php.net/archive/2026.php), [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce), [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))

## 3. Exploitation mechanics relevant to detection

### CVE-2026-109618 — controllable OOM

PHP historically used `longjmp()` to abort a request on OOM. An allocation can fail while request state is reachable but not fully initialized; shutdown can then read or branch on invalid state. The fix replaces that path with delayed soft-OOM handling at a VM safe point and a hard `_exit()` at a higher threshold. ([Upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))

The upstream advisory identifies these HTTP multipart OOM strategies:

- no usable declared content length;
- an excessive number of headers inside a multipart part;
- many empty file controls, which still create metadata arrays; and
- nested field names, which multiply generated array work.

Application-specific attacker-controlled allocations can also reach the vulnerable state, so these are hunting signals rather than a complete signature. `mod_php` has a confirmed application-independent path. FPM remains susceptible after successful startup through application-specific paths; the advisory also assesses FrankenPHP as likely susceptible and LSAPI as conditionally susceptible. ([Upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))

### CVE-2026-109619 — producer/consumer worker state

This flaw needs a **producer** operation that leaves request-owned state published and a **consumer** operation in a later request handled by the same worker. OOM, fatal/parse/compile failures, uncaught errors, failed `require`, and execution timeouts can interrupt a producer. A warning can also repopulate state after normal shutdown clearing. ([Upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))

Confirmed early consumers include diagnostics during per-request INI handling and session-upload-progress handling. The fatal-backtrace path has confirmed `mod_php` RCE; the session lifecycle path was validated against both `mod_php` and a normal dynamic FPM pool. Producer and consumer must reach the same worker, so exploit attempts may repeat requests to overcome pool routing. ([Upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))

Session upload progress is enabled by default. Its default multipart field is **`PHP_SESSION_UPLOAD_PROGRESS`**, but the name is configurable. ([PHP configuration manual](https://www.php.net/manual/en/session.configuration.php), [PHP upload-progress manual](https://www.php.net/session.upload-progress))

Wiz documents a disclosure path in which reclaimed memory is URL-encoded into a `PHPSESSID` response cookie. Its hunting guidance calls out unusual multipart uploads, repeated memory-limit failures or HTTP 500 responses, unexpected large/malformed `PHPSESSID` cookies, and worker churn. ([Wiz Research](https://www.wiz.io/blog/php2shell-php-rce))

## 4. Splunk-relevant observables

| Telemetry | Observable | Interpretation and limit |
|---|---|---|
| Cloudflare WAF | Any rule ID in §6. | Strong vendor signal. Keep action, host, path, source, Ray/request ID, and response-aware outcome. ([Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection)) |
| Proxy/WAF request | `multipart/form-data` to PHP with missing/unusable `Content-Length`, excessive per-part headers, many empty files, very long/nested form keys. | Candidate attempt only; each can be benign. Baseline by route. ([CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) |
| Request form metadata | `PHP_SESSION_UPLOAD_PROGRESS`, or the configured alternate name, on a route that does not use upload progress. | Candidate lifecycle trigger; legitimate PHP functionality, not malicious alone. ([PHP manual](https://www.php.net/manual/en/session.configuration.php)) |
| HTTP response | HTTP 500 bursts after suspicious multipart requests; unusually large/malformed `PHPSESSID` in `Set-Cookie`. | Possible exploit/disclosure. Response correlation materially raises confidence. ([Wiz Research](https://www.wiz.io/blog/php2shell-php-rce), [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection)) |
| PHP/Apache/FPM logs | Repeated pre-script warnings/deprecations/core errors; cleanup warnings; fatal, parse or uncaught errors; `Maximum execution time exceeded`; failures concentrated on attacker-controlled routes/content. | Upstream producer/exposure evidence. Absence is not proof of safety because a failure may precede logging. ([CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) |
| Process/service telemetry | PHP-FPM child churn or PHP/Apache crashes clustered around candidate requests. | Corroborating signal with ordinary-fault/deploy false positives. ([CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce)) |
| Sequence analytics | Same source/target/route produces a fatal/OOM-like request and later multipart/upload-progress requests in a short window. | Medium-confidence approximation of producer/consumer behavior; access logs rarely expose worker identity. ([CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) |
| EDR/audit | PHP worker launches a shell/tool, writes a file, or opens an outbound connection after the candidate request. | Corroborating outcome signal, not PHP2Shell-specific. Treat it as confirmed compromise only after verifying that the behavior is unauthorized and correlated to the request. ([CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)) |

Splunk already publishes two useful outcome-oriented baselines: [Web or Application Server Spawning Shell](https://research.splunk.com/endpoint/8fdb41ad-091c-4d7a-af1d-9123fe94b539/) and [Windows Suspicious Child Process Spawned From WebServer](https://research.splunk.com/endpoint/2d4470ef-7158-4b47-b68b-1f7f16382156/). Both require endpoint process telemetry mapped to the CIM `Endpoint.Processes` data model. For PHP2Shell, extend the locally approved parent list to cover the deployed SAPI/runtime (`php-fpm*`, `php-cgi*`, `lsphp*`, `frankenphp`, Apache/httpd, and relevant Windows equivalents), then baseline legitimate maintenance jobs before enabling notable alerts. These analytics identify a likely RCE outcome; they do not identify which PHP2Shell CVE or request path caused it.

## 5. Corelight open-source detection anchors

Corelight released an official [`corelight/php2shell-detect`](https://github.com/corelight/php2shell-detect) repository with Zeek and Suricata content. Corelight says its Zeek logic is behavioral and correlated, while its Suricata rules provide a rare POST-body marker plus PHP version inventory. Both require HTTP visibility; encrypted HTTP must be decrypted before inspection. ([Corelight research post](https://corelight.com/blog/php2shell-detection-before-disclosure?hs_amp=true), [Corelight repository](https://github.com/corelight/php2shell-detect))

If Zeek `notice.log` is ingested into Splunk, match these `PHP2SHELL::` notice types:

- `PHP_Crash_Sequence`
- `Multipart_Header_Flood`
- `Large_Form_Key`
- `Serialized_Integer_Overflow`
- `Serialized_Integer_Collisions`
- `Serialized_String_Collisions`
- `Serialized_Duplicate_Array`
- `Serialized_Object_Repetition`
- `Potentially_Affected_PHP_Version`

The package correlates by configured session cookies (default `PHPSESSID`) in a one-minute default window. It also attaches a sample network event in the notice `sub` field. Default thresholds include 128 repeated recognized MIME headers and a 65,536-byte form-name threshold; these are Corelight defaults, not universal maliciousness boundaries. ([Corelight repository](https://github.com/corelight/php2shell-detect))

If Suricata EVE is ingested, match `alert.signature_id`:

| SID | Meaning | Triage limit |
|---|---|---|
| **3000650** | Detection marker in a POST request body. | The repository warns the marker can appear legitimately and does not itself prove an exploit attempt. |
| **3000651** | Potentially affected PHP version in `Server` or `X-Powered-By`. | Inventory only; banners can be absent/rewritten and vendor builds can backport. |
| **3000652** | Potentially affected PHP version in a `phpinfo()`-shaped response body. | Inventory only; same version/backport limitation. |
| **3000653** | Serialized integer-key collision pattern in an HTTP request body. *Added to the repository after 2026-10-21; confirmed in the rules file on 2026-11-06.* | Check the repository README for current tuning guidance before alerting on it. |

These meanings and limitations come directly from the [Corelight repository](https://github.com/corelight/php2shell-detect). Suricata does not implement the Zeek package’s cross-request session correlation.

## 6. Cloudflare rule identifiers

Cloudflare says these rules were deployed for PHP2Shell. If Cloudflare security events reach Splunk, matching the IDs is stronger than reconstructing Cloudflare’s unpublished rule logic. ([Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))

**Managed Free Ruleset** `77454fe2d30c4220b5701f6fdfb893ba`:

`4e315666e8e344cdb64119a3b5ccf32f`, `00c10e6cc4da4bd08722adeebcd95984`, `48ddf592361e4fdb97a8a85982dab691`, `3556683d512a47f2937899c524b1a4c6`, `da07c85852e34625bb478496302ede46`, `19373a83abb840e18ab3ce5a7975ce1b`, `07f0b6ddaabf40b1b2042dade8d613fa`.

**Managed Ruleset** `efb7b8c949ac4650a09736fc376e9aee`:

`c1d409ad838f47f59446f21cc438d5dd`, `f9a45927414245e3a64bb12d0a0c2f64`, `771c654ae1154d4daa72f4e1545d163c`, `217005865f0145f392300bac212afcc9`, `38efdb17ea594501bb55a1d71867b12e`, `4148ae686fdb4d01be673fab9d9c073d`, `1389aa259617437392ce149c48143645`.

**Managed Response Firewall Default:** Cloudflare's post names this response-side protection and says it is deployed on all plans. It does **not** publish a rule ID for it. *(Correction 2026-11-06: the first draft listed an ID here that does not appear in Cloudflare's post, so it has been removed.)*

Cloudflare warns that descriptions may change and protections will evolve. Use IDs plus current managed-rule metadata, not a frozen description. ([Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))

## 7. Detection design and limits

1. **Layer severity.** A request anomaly or WAF match is an `attempt`, with the WAF action and origin outcome showing whether it was blocked; an anomaly plus PHP errors or worker churn is `possible exploitation`; response disclosure or verified unauthorized PHP-worker execution, writes, or network activity correlated to the request is `probable/confirmed compromise`. ([Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))
2. **Prefer correlation to a static regex.** Exploitation depends on allocator layout, worker reuse, build, extensions, frontend behavior, and sometimes multiple requests. Cloudflare observed payload mutation. ([CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))
3. **Collect request and response context.** Useful fields include source, destination, host, URI, method, content type, request length, content-length presence/value, transfer encoding, status, response length, `Set-Cookie` metadata, WAF rule/action, Zeek UID/Corelight notice, Suricata SID, and a transaction identifier. Cloudflare explicitly says request-only data can be insufficient. ([Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))
4. **Map local configuration.** Record SAPI, package/vendor build, `memory_limit`, `post_max_size`, `max_input_nesting_level`, `session.upload_progress.enabled`, `session.upload_progress.name`, PHP 8.5 `fatal_error_backtraces`, FPM pool settings, and worker recycling. These affect reachability and telemetry. ([PHP release advisory](https://www.php.net/archive/2026.php), [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))
5. **Detection is not remediation.** The PHP project states updating is the only complete mitigation. ([PHP release advisory](https://www.php.net/archive/2026.php))

No reviewed upstream advisory publishes a complete stable payload signature. Cloudflare’s rule logic is not public, and Corelight explicitly labels its POST marker as potentially legitimate. Legitimate uploads, application faults, and worker recycling can match individual traits. **Confidence is high for the CVE identity, mechanics, fixed supported versions, Cloudflare attack-attempt observation, rule IDs, and Corelight SIDs; confidence in any request-only heuristic is medium or lower until locally baselined.** ([Corelight repository](https://github.com/corelight/php2shell-detect), [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection))

All core sources were published or updated on the access date. Vendor backports, rule metadata, exploit variants, and exploitation status can change within hours; re-check PHP, Corelight, and Cloudflare before production tuning.

## 8. Primary sources

- [PHP project — critical RCE release advisory](https://www.php.net/archive/2026.php)
- [php/php-src — CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [php/php-src — CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP manual — session configuration](https://www.php.net/manual/en/session.configuration.php)
- [PHP manual — session upload progress](https://www.php.net/session.upload-progress)
- [Wiz Research — PHP2Shell technical disclosure](https://www.wiz.io/blog/php2shell-php-rce)
- [Corelight — detection research post](https://corelight.com/blog/php2shell-detection-before-disclosure?hs_amp=true)
- [Corelight — open-source Zeek and Suricata package](https://github.com/corelight/php2shell-detect)
- [Cloudflare — observed traffic and WAF rule IDs](https://blog.cloudflare.com/php-vulnerabilities-waf-protection)
- [Splunk Security Content — Web or Application Server Spawning Shell](https://research.splunk.com/endpoint/8fdb41ad-091c-4d7a-af1d-9123fe94b539/)
- [Splunk Security Content — Windows Suspicious Child Process Spawned From WebServer](https://research.splunk.com/endpoint/2d4470ef-7158-4b47-b68b-1f7f16382156/)

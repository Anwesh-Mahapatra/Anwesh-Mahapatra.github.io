---
layout: post
title: "Risky Entra ID sign-in → GCP API enablement: building a cross-cloud correlation rule in Google SecOps"
summary: "A YARA-L rule that links a risky Microsoft sign-in to someone switching on Google Cloud APIs. What the data really looked like, the bugs hiding in a 'simple' rule, how I proved a zero-result rule wasn't broken, and the blind spot Microsoft's offline risk creates."
tags: [google-secops, yara-l, entra-id, gcp, detection-engineering]
---

The request was short: *detect a medium or high risk Entra ID sign-in that wasn't blocked, followed by the same user trying to enable an API service in GCP, within 6 hours.*

It came with a draft rule. It compiled. On paper it looked right. In practice it would never have fired, and finding out why took a few hours of checking data rather than reading docs.

This is the full write-up: the idea, the data checks, the rule, how I tested a rule that returned zero results, and a gap in the whole approach that only showed up at the end.

> Details from the original environment (organisation, users, IPs, internal names and exact volumes) are removed or generalised. The techniques are what matter.

## Why this pair of events

Attackers who get hold of a cloud identity often go straight for **compute they don't pay for**: crypto mining, GPU workloads, or AI/LLM APIs. In GCP, almost all of that needs an API to be switched on first (Compute Engine, Vertex AI and so on).

So the story the rule looks for is:

1. A sign-in that Microsoft thinks is risky, but which **wasn't blocked**.
2. Shortly after, the **same person** asks GCP to enable an API.

MITRE mapping:

- **T1078.004 – Valid Accounts: Cloud Accounts** (Initial Access) for the risky sign-in that got through.
- **T1496.004 – Resource Hijacking: Cloud Service Hijacking** (Impact) for switching on cloud services to abuse.

To be honest about coverage: this catches a **likely precursor**, not proof of hijacking. Enabling an API is a normal admin action too.

## The draft logic

```text
// Event 1: medium/high risk sign-in, not blocked
$e1.metadata.log_type = "AZURE_AD"
$e1_user = $e1.target.user.email_addresses
( $e1.additional.fields["riskLevelDuringSignIn"] = /high|medium/ or
  $e1.additional.fields["riskLevelAggregated"]   = /high|medium/ or
  $e1.security_result.detection_fields["riskLevelDuringSignIn"] = /high|medium/ or
  $e1.security_result.detection_fields["riskLevelAggregated"]   = /high|medium/ )
$e1.security_result.action != "BLOCK"

// Event 2: GCP API enablement attempt
$e2.metadata.log_type = "GCP_CLOUDAUDIT"
$e2.metadata.product_event_type = "google.api.serviceusage.v1.ServiceUsage.EnableService"
$e2_user = $e2.principal.user.email_addresses

$e1.metadata.event_timestamp.seconds < $e2.metadata.event_timestamp.seconds
$e1_user = $e2_user
match: $e1_user over 6h
```

Reasonable at a glance. Instead of trusting it, I checked every assumption against real events first.

## Step 1: where does the risk level actually live?

The Entra sign-in parser offers two plausible places for `riskLevelDuringSignIn` / `riskLevelAggregated`. A quick stats search answers it:

```text
metadata.log_type = "AZURE_AD"
security_result.detection_fields["riskLevelDuringSignIn"] = /high|medium/ nocase
  OR security_result.detection_fields["riskLevelAggregated"] = /high|medium/ nocase
$action = security_result.action
match:
  $action
outcome:
  $events = count_distinct(metadata.id)
```

- The risk values are in **`security_result.detection_fields`**. The `additional.fields` branches matched nothing; I kept them only as a harmless fallback.
- Along the way I made a mistake worth sharing: I first filtered on `detection_fields.key = /high|medium/`. That returns nothing, because **`.key` holds the field name** (`riskLevelDuringSignIn`), not the value. Use the map syntax `detection_fields["name"]`.

### The `UNKNOWN_ACTION` trap

My first version used `count(metadata.id)`. The result had a huge `UNKNOWN_ACTION` bucket, roughly **15× the real number of events**. It looked like most risky sign-ins had no outcome at all.

They didn't. Two things were going on:

- **`security_result` is a repeated field.** One sign-in event carries several `security_result` entries, and only one of them has the action. Grouping by `$action` creates one row per *entry*, not per *event*.
- **`UNKNOWN_ACTION` is just how stats shows an empty value.** Searching `security_result.action = "UNKNOWN_ACTION"` returns nothing.

Switching to `count_distinct(metadata.id)` collapsed it to sensible numbers. Most risky sign-ins were blocked; a small slice was allowed, and that slice is what the rule cares about.

> **Rule of thumb:** in SecOps stats, always count with `count_distinct(metadata.id)` when grouping by anything that sits on a repeated field.

### Does `!= "BLOCK"` really mean "not blocked"?

On a repeated field, `field != "X"` passes if **any** entry isn't `X`. So a blocked sign-in that also has an empty `security_result` entry can slip through.

I compared two searches over the same 30 days:

```text
security_result.action != "BLOCK"          // draft version
NOT security_result.action = "BLOCK"       // "no entry is BLOCK"
```

Both returned **exactly the ALLOW count**. No leak in this data, but it's a latent bug, so the final rule uses the explicit form:

```text
all $e1.security_result.action != "BLOCK"
```

## Step 2: the GCP side

```text
metadata.log_type = "GCP_CLOUDAUDIT"
metadata.product_event_type = /serviceusage\.(enableservice|batchenableservices)$/ nocase
$method = metadata.product_event_type
$status = security_result.detection_fields["status_code"]
match:
  $method, $status
outcome:
  $events = count_distinct(metadata.id)
  $users = count_distinct(principal.user.email_addresses)
```

Three findings:

1. **The method name was stored in lowercase** (`...serviceusage.enableservice`). YARA-L string comparison is case-sensitive by default, so the draft's exact match on `ServiceUsage.EnableService` would **never have matched anything**. The search UI hid this because it had *Case Sensitivity Off*. Fix: a regex with `nocase`.
2. **`BatchEnableServices` matters.** It's the same action (several APIs at once) and accounted for roughly a sixth of all enablement events. An attacker can use either.
3. **Failures exist.** Status `7` is `PERMISSION_DENIED`. The request explicitly wanted *success or failure*, which makes sense: a denied attempt by a compromised account is still a strong signal.

## Step 3: the rule

```text
rule risky_entra_signin_followed_by_gcp_enable_service {
  meta:
    description = "Medium/high risk Entra ID sign-in with no recorded BLOCK, followed within 6h by the same user attempting to enable a GCP API service"
    severity = "High"
    tactic = "TA0001, TA0040"
    technique = "T1078.004, T1496.004"

  events:
    // Event 1: risky sign-in, nothing on it is BLOCK
    $e1.metadata.log_type = "AZURE_AD"
    $e1.metadata.event_type = "USER_LOGIN"
    (
      $e1.security_result.detection_fields["riskLevelDuringSignIn"] = /^(high|medium)$/ nocase or
      $e1.security_result.detection_fields["riskLevelAggregated"]   = /^(high|medium)$/ nocase or
      $e1.additional.fields["riskLevelDuringSignIn"] = /^(high|medium)$/ nocase or
      $e1.additional.fields["riskLevelAggregated"]   = /^(high|medium)$/ nocase
    )
    all $e1.security_result.action != "BLOCK"
    $e1_user = strings.to_lower($e1.target.user.email_addresses)

    // Event 2: GCP API enablement attempt (success or failure)
    $e2.metadata.log_type = "GCP_CLOUDAUDIT"
    $e2.metadata.product_event_type = /serviceusage\.(enableservice|batchenableservices)$/ nocase
    $e2_user = strings.to_lower($e2.principal.user.email_addresses)

    // same person, sign-in first
    $e1_user = $e2_user
    $e1_user != ""
    $e1.metadata.event_timestamp.seconds < $e2.metadata.event_timestamp.seconds

  match:
    $e1_user over 6h

  outcome:
    $risk_score = 80

  condition:
    $e1 and $e2
}
```

What changed from the draft, and why:

| Change | Why |
|---|---|
| `nocase` regex on the GCP method | Stored value is lowercase; the exact match never fired |
| Added `BatchEnableServices` | Same action, a big share of real events |
| `strings.to_lower()` on both emails | UPN casing differs between systems |
| `$e1_user != ""` | Function-derived match variables don't get automatic empty-value filtering, so blanks would join with blanks |
| `metadata.event_type = "USER_LOGIN"` | Only real sign-ins should qualify, not any Entra event carrying risk fields |
| Anchored `^(high\|medium)$` | Match the exact value, not anything containing it |
| `all ... != "BLOCK"` | Correct semantics on a repeated field |

The rule also records its limits in the metadata: ordering uses whole seconds (a sign-in and an enablement in the same second won't match, an accepted edge case), and the identity join assumes the Entra UPN equals the Google identity email.

## Step 4: testing a rule that returns nothing

SecOps lets you test a rule over at most **~14 days at a time**, so I ran two back-to-back windows covering about four weeks.

**Both returned zero.**

Zero is the most dangerous test result, because "nothing happened" and "the rule is broken" look identical. The most likely way for this rule to be silently broken was the **identity join**: if Entra and GCP identify people differently (different domains, service accounts, aliases), the two sides never meet.

So I ran a **loosened test**: comment out only the risk and BLOCK conditions, leaving the join intact.

```text
// (
//   $e1.security_result.detection_fields["riskLevelDuringSignIn"] = ...
//   ...
// )
// all $e1.security_result.action != "BLOCK"
```

Now the rule means *"any sign-in, then a GCP API enablement, by the same person"*. If the join works, normal admins doing normal work should light it up.

It hit the **test detection limit** almost immediately. That proved:

- Entra and GCP users **do** match on the same email.
- The full rule's zero is **real**: nobody enabling GCP APIs had a risky, unblocked sign-in beforehand in that period.

Then I restored the conditions and saved the rule. It's a quiet, high-fidelity correlation, which is what you want at High severity.

> **Technique worth reusing:** when a correlation rule returns zero, remove the *selective* conditions but keep the *join*. Hits mean the plumbing works and the zero is genuine. Still zero means your join is broken.

## Single multi-event rule vs composite rule

The request mentioned a composite rule (rule chain): two base rules producing detections, plus a composite rule correlating those detections. I built it as a single multi-event rule instead and explained why.

**Composite makes sense when:**

- The base signals are reusable building blocks for other chains.
- You want to tune or add exclusions per stage.
- You expect to add more stages later (e.g. *then* a new VM is created).

**A single rule is better here because:**

- It's only two events and one join, so one rule is simpler to read and maintain.
- A composite silently stops working if someone disables a base rule.
- Each base rule here would generate a steady stream of low-value detections that someone has to keep non-alerting.
- The single rule already does exactly what was asked, and testing proved it.

## Taking outside review with a pinch of salt

I also ran the rule past another AI model for a "static review". It produced a long list of High findings. Some were genuinely useful and went in: the `USER_LOGIN` filter, `all` on the repeated field, anchored regexes, softer analyst steps (don't disable a service just because a *failed* enable request appeared).

Others were already answered by data I'd checked: identity mapping, field locations, whether actions are ever missing. And some test cases (synthetic same-second events, exact 6-hour boundaries) need injected test data you rarely get in someone else's production tenant.

A review written **without your data** is a list of hypotheses. Your searches are what settle them.

## The blind spot: Microsoft's offline risk

The last finding changed how I think about any rule built on Entra sign-in risk.

Microsoft calculates sign-in risk in two ways:

- **Real-time detections** happen during the sign-in (anonymous IP, unfamiliar properties). They're written into the sign-in log.
- **Offline detections** happen later, after Microsoft has more context: atypical travel, malicious IP, anomalous token, adversary-in-the-middle, suspicious MFA prompts. Microsoft says these can take **up to 48 hours**.

The sign-in log is streamed to the SIEM **once**, as a snapshot. When an offline detection raises the risk later, the portal shows the new value, but the SIEM's copy keeps the old one. So **the rule above can't see offline risk at all.**

Offline detections still arrive, just somewhere else: as **Entra ID Protection alerts through the Microsoft Graph security alerts feed** (`MICROSOFT_GRAPH_ALERT`, product name `AAD Identity Protection`). Checking that feed showed:

- Offline-type alerts were a meaningful share of all Identity Protection alerts, and they're the high-value ones (AiTM, anomalous token, leaked-credential style signals).
- **The alert's timestamp is when the alert was created, not when the sign-in happened.** In the example I traced, the alert landed about **10.5 hours** after the sign-in. A 6-hour window would have missed it entirely.
- **The user lands in different UDM fields** depending on alert type (`target.user.email_addresses` for some, `principal.user.email_addresses` for others).

That leads to a companion design:

```text
// Event 1: Identity Protection alert (real-time or offline)
$e1.metadata.log_type = "MICROSOFT_GRAPH_ALERT"
$e1.metadata.product_name = "AAD Identity Protection" nocase
$e1_user = strings.to_lower(strings.coalesce(
             $e1.target.user.email_addresses,
             $e1.principal.user.email_addresses))

// Event 2: same GCP enablement as before
...

$e1_user = $e2_user
$e1_user != ""
// NO ordering: the GCP activity can happen before the alert exists
match:
  $e1_user over 48h
```

Key differences: **no ordering**, a **48-hour window**, and no `USER_LOGIN` filter because alert event types vary. I treat this as optional, since these alerts usually already page someone on their own; the companion rule's value is escalating them when cloud abuse follows. A lighter alternative is a SOAR enrichment step on Identity Protection alerts that checks for recent GCP API enablements by the same user.

## A real alert, traced end to end

To understand the timing, I picked one offline alert and followed it all the way down. It's a good example of why the *type* of alert isn't the whole story.

**The alert:** *sign-in from an atypical location*. Atypical travel compares two sign-ins that are too far apart, too quickly.

**The user's sign-ins that day** (grouped by IP and location):

- Almost everything came from their home country through the corporate proxy's local nodes, plus one home ISP address. All normal.
- One IP stood out: a **cloud provider address in a US data-centre region**, with about 16 sign-ins over ~5 hours.
- One of those cloud sign-ins was **5 seconds** after a normal one from the user's own country. Nobody travels that fast.

**What the cloud IP was doing:**

```text
metadata.log_type = "AZURE_AD"
target.user.email_addresses = "user@example.com" nocase
principal.ip = "<the cloud IP>"
$app = target.application
$ua = network.http.user_agent
$action = security_result.action
match:
  $app, $ua, $action
outcome:
  $events = count_distinct(metadata.id)
```

- **App:** a database JDBC client driver.
- **User agent:** a Java HTTP client, not a browser.
- **Action:** every attempt **BLOCKED**.

**Why it was blocked:**

```text
$summary = security_result.summary
$reason = security_result.description
```

The reason text was Microsoft's message for **error 50076: MFA required**.

That last detail flips the conclusion. Entra only asks for MFA **after the password is correct**. So:

- Most likely: a scheduled job on a cloud VM was connecting to a database **using a person's own account**, and failing because a non-interactive job can't do MFA. That's harmless but bad practice; it should be a service account or managed identity.
- If the user doesn't recognise the job: someone has their **valid password**, and MFA was the only thing that stopped them. That means a password reset and session revocation.

Either way it needs a human to confirm. In the environment I looked at, this alert had already been **closed**, quite possibly without anyone noticing that MFA was the only control left standing.

## Takeaways

- **Check the data before trusting the logic.** Field location, value casing and repeated-field behaviour broke this rule more than the logic did.
- **`count_distinct(metadata.id)`**, not `count()`, whenever repeated fields are involved.
- **On repeated fields, say what you mean:** `all field != "X"` vs `field != "X"` are different rules.
- **A zero-result test proves nothing on its own.** Loosen the selective conditions, keep the join, and confirm it can fire.
- **Sign-in risk in your SIEM is a snapshot.** Offline risk arrives later, through a different feed, with a different timestamp meaning.
- **"Blocked by MFA" on a failed sign-in means the password worked.** Treat it accordingly.

## References

- [Composite detections – Google SecOps](https://docs.cloud.google.com/chronicle/docs/yara-l/composite-detection-rules)
- [Repeated fields in YARA-L](https://docs.cloud.google.com/chronicle/docs/yara-l/repeated-fields)
- [Risk detection types and levels – Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/concept-risk-detection-types)
- [signIn resource type – Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0)
- [Service Usage audit logging – Google Cloud](https://docs.cloud.google.com/service-usage/docs/audit-logging)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/) · [T1496.004](https://attack.mitre.org/techniques/T1496/004/)

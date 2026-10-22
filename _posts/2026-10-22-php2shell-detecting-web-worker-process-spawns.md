---
layout: post
title: "PHP2Shell: detecting the shell, not the exploit"
summary: "Two critical PHP flaws went public before most teams could patch. Here's how I turned a threat-intel draft rule into a detection that fits real data: baseline first, match on what's actually logged, and test 90 days with a 14-day tester."
tags: [google-secops, yara-l, php, cve-2026-109618, detection-engineering]
---

On 20 October 2026, details of two remote code execution flaws in PHP itself leaked ahead of their planned disclosure. Now known as PHP2Shell (CVE-2026-109618 and CVE-2026-109619), both are rated CVSS 9.2. They sit in PHP's core, not in any one application, so any server running PHP to answer web requests is in scope. PHP shipped fixes the next day in 8.5.12, 8.4.27, 8.3.36 and 8.2.35. PHP 5 and 7 get nothing. Reports still disagree on whether either flaw is being exploited in the wild.

When a bug like this lands, the first question is "can we detect exploitation?" The honest answer is usually "not the exploit itself". The trigger is a crafted request that pushes PHP into an out-of-memory error or leaves stale state behind in a worker, and nothing in a typical log says "memory corruption happened here". What you *can* see is what an attacker does next. The point of an RCE is to run commands, so sooner or later PHP or the web server starts a program it has no business starting.

So that's what I built the detection around.

## Start from the draft, then look at the data

I started from a threat-intel advisory that came with a draft detection rule. As with the AI-written rule in my [last post](/2026/10/risky-entra-sign-in-to-gcp-api-enablement/), it was a sensible starting point and a poor finished product, because it was written without seeing the environment it would run in.

Before touching the logic, I spent time on three questions in UDM search, over the last 90 days:

**Where does PHP actually run?** Not where you *think* it runs. The surprise was that PHP showed up mostly inside other vendors' products. Plenty of security and management tools ship their own copy of PHP to power their web consoles. Nobody thinks of those boxes as "PHP servers", and a normal PHP update doesn't touch them, because the vendor has to ship the patch. The PHP2Shell advisories also list network appliances that bundle PHP. If your inventory only covers "our web apps", it will miss these.

**What do web workers normally start?** This is the baseline, and it decides how noisy the rule will be. In my data, PHP processes started **no other programs at all** in 90 days. Web servers did start a few things, but never the shell and download tools an attacker reaches for.

**What do the logs actually record?** The draft rule leaned on command-line arguments. On some of the hosts that mattered, command lines simply weren't being collected, so a rule built on them would silently skip exactly the machines at risk. Program names and paths were present much more consistently, so the rule matches on those.

## The rule

Two ideas, one rule:

1. **PHP starting anything is suspicious**, because the baseline says it never happens.
2. **A web server starting a known attacker tool is suspicious**, even though web servers start other things legitimately.

```text
rule web_worker_spawning_high_risk_process {
  meta:
    description = "PHP starting any process, or a web server starting a high-risk tool (possible PHP2Shell / web shell activity)"
    severity = "High"
    tactic = "TA0002"
    technique = "T1505.003, T1059"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $parent = strings.to_lower($e.principal.process.file.full_path)
    $child  = strings.to_lower($e.target.process.file.full_path)
    (
      // 1) PHP should never start another program
      re.regex($parent, `[\\/]php[^\\/]*$`)
      or
      // 2) a web server starting a shell or download tool
      (
        re.regex($parent, `[\\/](w3wp|httpd|apache2|nginx)(\.exe)?$`) and
        re.regex($child,  `[\\/](cmd|powershell|pwsh|whoami|certutil|curl|wget|sh|bash)(\.exe)?$`)
      )
    )

  outcome:
    $risk_score = 85
    $parent_process = $parent
    $child_process = $child

  condition:
    $e
}
```

A few choices worth explaining:

- **Paths are lowercased** so `PHP.EXE` and `php.exe` match the same way. Case-sensitive matching is a classic silent failure in YARA-L.
- **`[\\/]php[^\\/]*$` matches the file name, not the whole path.** It catches `php.exe`, `php-cgi.exe` and `php-fpm8.3`, wherever they're installed, including inside a vendor's own folder.
- **The tool list is a starting point, not a complete list.** Extend it with what your own baseline shows.
- **No command-line conditions**, for the reason above: a condition on a field that isn't collected doesn't fail loudly. It just never matches.

## Testing 90 days with a 14-day tester

The rule tester in Google SecOps only runs over about 14 days at a time. A baseline built on 90 days deserves a test over 90 days, so I ran it as consecutive 14-day windows back to back until the whole period was covered.

It returned zero hits. That matched the baseline, and that's the point. For a rule like this, zero over a long, representative window is what earns it High severity: when it does fire, someone should look straight away.

A zero can also mean a broken rule, though. Two quick checks rule that out:

- **Run the two halves separately as UDM searches** (`principal.process.file.full_path = /php/ nocase`, and the web-server parent search) to prove the parent processes exist in the data at all.
- **Temporarily widen the child list**, for example to any child process, and confirm the web-server branch fires on normal activity. Then restore it.

## Detection isn't the fix

This rule buys time. It doesn't close the hole. The real actions are still:

- **Patch**, and for vendor-bundled PHP, chase the vendor's advisory, because your OS update won't reach it.
- **Close the logging gaps** the baseline exposes. A server you can't see process activity on is a server this rule can't protect.
- **Check the appliances.** If a firewall or remote-access gateway bundles PHP, it needs a firmware update, not a package update.

The pattern generalises beyond PHP. When the exploit is invisible, detect the behaviour that has to follow it, and build the rule on what your logs actually contain, not on what the draft assumed they would.

## References

- [PHP2Shell FAQ – watchTowr](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [PHP2Shell technical summary and mitigations – threatlandscape.io](https://threatlandscape.io/blog/php-core-rce-cve-2026-109618-109619-leak-ahead-of-embargo)
- [PHP2Shell: mass exploitation looms – SecurityWeek](https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/)
- [YARA-L rule examples – Google SecOps](https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples)
- [MITRE ATT&CK T1505.003 – Web Shell](https://attack.mitre.org/techniques/T1505/003/)

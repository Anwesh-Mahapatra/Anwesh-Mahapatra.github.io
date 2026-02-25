---
layout: post
title: "LockBit in the Lab: From Raw Sysmon to High-Signal Detections"
date: 2026-02-25
categories: [Detection Engineering, DFIR, Splunk, Cribl]
tags: [lockbit, sysmon, splunk, cribl, hunting, detections]
author: Anwesh
---

## Why this post exists
I wanted a repeatable way to learn ransomware detection engineering using **realistic telemetry** (Sysmon) and a **real ingestion pipeline** (Cribl → Splunk).  
This post covers:

- The *minimum plumbing* needed to ingest data
- The dataset used (LockBit Sysmon)
- A **hunt method** that scales beyond “scroll and pray”
- A small set of **high-signal detections** you can ship

> If you want a deep plumbing-only guide (Cribl internals, routes, scaling, replay tooling), that’ll be a separate post.

---

## Lab architecture (minimal but real)
**Goal:** Reproduce an enterprise-ish ingestion path, not “upload a CSV and call it DFIR”.

### Components
- **Dataset host (`labctl`)**: holds attack datasets and replays events
- **Cribl (Leader + Worker)**:
  - Raw HTTP Source accepts events
  - Pipeline parses/enriches (dataset, timestamps, sourcetype/index routing)
  - Route sends to Splunk
- **Splunk**:
  - HEC token receives events into `lab_attack`
  - Sysmon TA (or equivalent parsing) makes fields usable (`EventCode`, `Image`, `CommandLine`, etc.)

### Flow
`attack dataset (sysmon.log) → replay → Cribl Raw HTTP Source → Cribl pipeline → Splunk HEC → Splunk index`

---

## Dataset: LockBit Sysmon from Splunk Attack Data
I used the **Splunk Attack Data** repository dataset for LockBit ransomware.

- Dataset: `datasets/malware/lockbit_ransomware/sysmon.log`
- Sourcetype mapped: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Index used: `lab_attack`

This matters because it mimics real-life: you rarely get “pretty JSON”. You get logs. Lots of logs.

---

## Ingestion summary (what I actually did)
### In Splunk
- Created index: `lab_attack`
- Created HEC token with permission to write to `lab_attack`

### In Cribl
- Raw HTTP Source: `/ingest/<dataset>`
- Pipeline:
  - parse incoming payload
  - normalize fields (`dataset`, `event_time`)
  - set Splunk metadata fields (`index`, `sourcetype`, `source`)
- Route:
  - Source: Raw HTTP
  - Pipeline attached
  - Destination: Splunk HEC

After replay, data appeared under:
- `index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

---

# 2) Hunting method (works when you have 10k–500k events)

## Step 0: Find the hunt window (bursts + scope)
**No one hunts effectively across “All time”.**
Start with volume-by-host.

```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| timechart span=5m count by Computer limit=20
```

Then lock your timeline bounds per host:

```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| stats count as events earliest(_time) as first latest(_time) as last by Computer
| eval first=strftime(first,"%F %T %z"), last=strftime(last,"%F %T %z")
| sort - events
```

---

## Step 1: Confirm telemetry coverage (what you can detect)
```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| stats count by Computer EventCode
| sort Computer - count
```

For ransomware hunts, the money EventCodes are:
- **1** Process creation (who ran what)
- **11 / 23** File create/delete (payload staging + impact)
- **12 / 13** Registry activity (extensions, persistence, config changes)
- **3** Network connections (delivery / C2) *(not always present in datasets)*

---

## Step 2: Build a seed list (rare executions)
Strip obvious noise and rank executables.

```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| eval img=lower(Image), pimg=lower(ParentImage)
| search NOT (img="*splunk*" OR img="*sysmon*" OR img="*msmpeng.exe*" OR img="*svchost.exe*")
| stats count min(_time) as first max(_time) as last values(Computer) as Computer values(User) as User values(ParentImage) as ParentImage values(CommandLine) as CommandLine by Image
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
| sort 0 count
```

In my run, suspicious seeds included:
- `C:\Temp\ConfirmEmail.exe`
- `C:\Program Files\7-Zip\7zG.exe`
- `C:\Windows\System32\rundll32.exe ... SHCreateLocalServerRunDll ... -Embedding`

---

## Step 3: Pivot to impact (ransom notes + extension registration)
Once you identify the ransomware executable (in this dataset: `ConfirmEmail.exe`), you care about:
- **mass file writes** (ransom note fanout)
- **new extension registration** (HKCR)
- **icon drop** (ProgramData)

---

# 3) Detections (high signal, low noise)

## Detection 1: Ransom note fanout (Sysmon EID 11)
Detect a single process writing the ransom note into many directories quickly.

```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=11 TargetFilename="*\\cHpfiXA9s.README.txt"
| eval dir=replace(TargetFilename,"\\\\[^\\\\]+$","")
| stats count as note_writes dc(dir) as unique_dirs values(dir) as sample_dirs by Computer Image ProcessGuid
| where unique_dirs >= 25
| sort - unique_dirs
```

---

## Detection 2: New encrypted extension registered in HKCR (Sysmon EID 13)
Ransomware often registers an extension so Explorer/Windows “understands” the new file type and icon association.

```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=13
TargetObject="HKCR\\.*\\(Default)"
| eval ext=replace(TargetObject,"^HKCR\\\\\\.","")
| eval ext=replace(ext,"\\\\\\(Default\\\\)$","")
| stats count as writes values(Image) as images values(Details) as details by Computer User ext
| where ext!="txt" AND ext!="log"
| sort - writes
```

---

## Detection 3: HKCR extension + ProgramData icon drop in 5 minutes (strong correlation)
This is “ransomware branding behavior” correlation.

```spl
index=lab_attack source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode=13 AND like(lower(TargetObject),"hkcr\\.%\\(default)"))
OR (EventCode=11 AND lower(TargetFilename)="c:\\programdata\\chpfixa9s.ico")
| eval ext=case(
    EventCode=13, replace(lower(TargetObject),"^hkcr\\\\\\.",""),
    true(), null()
  )
| eval ext=if(EventCode=13, replace(ext,"\\\\\\(default\\\\)$",""), ext)
| bucket _time span=5m
| stats values(ext) as exts values(TargetFilename) as icon_files values(Image) as images
       dc(eval(if(EventCode=13, TargetObject, null()))) as hkcr_writes
       dc(eval(if(EventCode=11, TargetFilename, null()))) as icon_writes
  by _time Computer User
| where hkcr_writes>0 AND icon_writes>0
| sort 0 _time
```

---

## What I’d ship to production (if I had to choose only 2)
1) **Ransom note fanout**
2) **HKCR extension + icon drop correlation**

Because those two are:
- high confidence
- low dependence on missing network telemetry
- resilient across many ransomware families (with minor adjustments)
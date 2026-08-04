---
layout: post
title: "Build a Detection Engineering Agent"
date: 2026-08-05
categories: [Detection Engineering, Tooling]
tags: [elasticsearch, detection-engineering, python, ai-agents]
author: Anwesh
---

*mappings lie, but the data doesn't — so don't hand the agent the mapping, hand it the data.*

Your SIEM can hand you a blueprint of every field it knows about. What it won't hand you is which of those fields actually have data in them. And it definitely won't tell you something like "this particular field has 3% coverage across your logging infra."

That gap matters more than it sounds. If you want an AI agent to write detection rules or generate response playbooks on top of your data, it needs to know what's actually there and not what the mapping claims might be there. So this is a codebase that answers that question properly, plus some other math we'll get into along the way.

The file is `field_atlas.py`. Let's start.

## What the script actually needs to do

Three things, at the core:

1. **Is there data?** — Count documents.
2. **Is the data fresh?** — Check the newest `@timestamp`.
3. **Which fields actually contain values?** — Measure field coverage and inspect sample values.

And one constraint shapes everything else: this has to run as a tool an agent calls. We can't have it searching petabytes of data every time it's invoked. What the agent actually gets is a summary, in JSON, that describes the data and not the data itself.

## Setting up something to point it at

Before any of this works, we need a data stream to query. Here's the actual walkthrough, request by request.

**1. Create an index template that says "anything named `people` is a data stream":**
```
PUT http://localhost:9200/_index_template/people-template
```
```json
{
  "index_patterns": ["people"],
  "data_stream": {},
  "priority": 200
}
```
![index template created](/assets/images/17.png)

**2. Index a document with a timestamp — this auto-creates the data stream:**
```
POST http://localhost:9200/people/_doc
```
```json
{
  "@timestamp": "2026-08-04T00:00:00Z",
  "process": { "parent": { "name": "cmd.exe" } }
}
```
![document indexed, 201 Created](/assets/images/18.png)

**3. Confirm the data stream actually exists:**
```
GET http://localhost:9200/_data_stream
```
![data stream listing showing people](/assets/images/19.png)

**4. Get the count:**
```
POST http://localhost:9200/people/_count
```
![count response](/assets/images/20.png)

**5. Ask for the newest timestamp via aggregation, the idea being we don't fetch every document just to find which one has the newest timestamp; we let Elasticsearch do that calculation server-side and not us:**
```
POST http://localhost:9200/people/_search
```
```json
{ "size": 0, "aggs": { "newest": { "max": { "field": "@timestamp" } } } }
```
![newest timestamp aggregation](/assets/images/21.png)

That's the setup, one real document sitting in a real data stream, ready for the rest of the script to interrogate.

## Q1: does it exist, and is it fresh?

```python
def existence(stream):
    total = post(f"/{stream}/_count", {})["count"]
    newest = None
    if total:
        resp = post(f"/{stream}/_search", {
            "size": 0,
            "aggs": {"newest": {"max": {"field": "@timestamp"}}},
        })
        newest = resp["aggregations"]["newest"].get("value_as_string")
    return total, newest
```

Two Elasticsearch calls, notice that we have `size: 0`, never to fetch the actual documents, just ask ES to count and compute. And also notice if `total` is zero, we don't even bother asking for the newest timestamp.

## Q2: what fields *could* exist?

The mapping we'd get here is just a blueprint. It says: if a document has a field called X, here's the type it'll be. A blueprint isn't proof of anything actually built. A stream can have 300 mapped fields where 250 of them never got populated due to parser malfunction, an abandoned log source,  or whatever the reason is. The blueprint doesn't know the difference between "used constantly" and "never used"

Think about it like a detection engineer: before writing any detection, you search the raw log first, find which fields hold the data you're after, then run a stat query to confirm that field is actually populated across *all* the log categories you care about. You don't want detection logic built on a field that only shows up in half your log sources.

Elasticsearch has an endpoint for the blueprint:

```
GET http://localhost:9200/people/_field_caps?fields=*
```
![field_caps response](/assets/images/22.png)

Most of that response is Elasticsearch talking about itself. `_routing`, `_inference_fields`, `_doc_count`, `_ignored_source`, `_index`, `_feature`, `_index_mode`, `_ignored`, `_tier`, `_seq_no`, `_nested_path`, `_field_names`, `_data_stream_timestamp`, `_source`, `_id`, `_version`. Sixteen fields, and not one of them is something a detection engineer would ever write a query against. `"metadata_field": true` is basically telling us that this is a elastic metadata field.

```python
def declared_leaf_fields(stream):
    caps = get(f"/{stream}/_field_caps", params={"fields": "*"})["fields"]
    out = {}
    for name, types in caps.items():
        for tname, info in types.items():
            if info.get("metadata_field"):
                continue
            if tname in ("object", "nested"):
                continue
            if name.endswith(".text"):
                continue
            out[name] = tname
    return out
```

### A quick caveat about the demo data

Worth flagging: the `people` index in these examples has no real ECS mapping behind it as you saw we just indexed a raw document and let Elasticsearch's dynamic mapping guess. So the real world response would like the below 3 blocks. Coz in real deployments, the parser pipeline would do the ECS mapping before the data is being sent to elasticsearch

```json
"process.parent": {
    "object": { "type": "object", "metadata_field": false, ... }
}
```
Not a searchable field, it's the folder our field `process.parent.name` lives inside.

```json
"process.parent.name": {
    "text": { "type": "text", "metadata_field": false, ... }
}
```
Elasticsearch's dynamic-mapping guess at the base type.

```json
"process.parent.name.keyword": {
    "keyword": { "type": "keyword", "metadata_field": false, ... }
}
```
And its auto-added keyword twin.

![text and keyword pair side by side](/assets/images/23.png)

In a real SIEM deployment you'd only find the keyword variant, because the mapping gets defined ahead of time by your parser pipeline — following the actual ECS convention, which names things the other way around:

```json
"process.parent.name": {
    "keyword": { "type": "keyword", "metadata_field": false, ... }
}
"process.parent.name.text": {
    "text": { "type": "text", "metadata_field": false, ... }
}
```

Run *that* through `declared_leaf_fields()`:
- `process.parent` → dropped, it's an `object`
- `process.parent.name` → survives, doesn't end in `.text`, isn't a container, isn't metadata
- `process.parent.name.text` → dropped, `name.endswith(".text")` catches it

So the filter is written for the ECS convention, not the dynamic-mapping-guess convention. On real SIEM data, it should collapse each field down to one clean keyword entry. On a toy, dynamically-mapped index, you'll see both the text and keyword variant survive. Worth knowing before you run this against your own cluster.

## Q3a: okay, but how much of it is real?

Knowing a field *could* exist still isn't the same as knowing it *does*. This is where we finally get to answer: "this field has 3% coverage in your logging infra."

```
POST http://localhost:9200/people/_search
```
```json
{
  "size": 0,
  "track_total_hits": true,
  "aggs": {
    "field_check": {
      "filter": { "exists": { "field": "process.parent.name.keyword" } }
    }
  }
}
```
![exists filter response, doc_count 1](/assets/images/24.png)

That gives you the doc count for one particular field. Divide by the total document count, and that's your coverage percentage.

So now let's actually code it and learn a bit.

## The problem with naming aggregations after fields

The request body above hardcodes one field name i.e `field_check` as the aggregation's label. But I don't want to loop using the field name itself as the label. Two reasons: some field names (like `@timestamp`) don't play nice as aggregation names, and I've got potentially hundreds of fields to check, not one.

So instead: build a map, something like `0: "@timestamp"`, `1: "process.parent.name.keyword"`. The real field names live in a plain list, `names = ["process.parent.name.keyword", "@timestamp"]`, and the aggregation gets labeled by *position* instead of by the actual names of the fields. And that `names` list isn't typed by hand — it's the direct output of `declared_leaf_fields()` above.

## Batching, because Elasticsearch has limits

There's a second problem hiding here: if a stream has 300 declared fields, you can't cram 300 aggregations into a single request. Elasticsearch will choke, and the response would be unreadable anyway. So instead of one giant request, we send many small ones — 50 fields' worth of aggregations at a time.

```python
BATCH = 50

def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
```

This part isn't Elasticsearch-specific — it's a general Python trick for slicing a big list into smaller, fixed-size pieces. The `yield` is doing something specific: instead of building *all* the batches into a list up front, `chunks()` hands back one batch at a time, computed only when the loop asks for the next one. For 300 fields split into groups of 50, that's 6 batches, but only one of them exists in memory at any given moment. Same instinct as chunking a big list of IDs before hitting a bulk API that caps how many you can send per call, never send more than the receiving end can handle in one go.

Combine the positional-naming trick with the batching, and coverage looks like this:

```python
def coverage(stream, names):
    total = 0
    counts = {}
    for chunk in chunks(names, BATCH):
        aggs = {str(i): {"filter": {"exists": {"field": f}}} for i, f in enumerate(chunk)}
        resp = post(f"/{stream}/_search", {
            "size": 0,
            "track_total_hits": True,
            "aggs": aggs,
        })
        total = resp["hits"]["total"]["value"]
        for i, f in enumerate(chunk):
            counts[f] = resp["aggregations"][str(i)]["doc_count"]
    return total, counts
```

`track_total_hits: true` matters here coz elasticsearch stops counting hits at 10,000 by default for performance and then it gives giberish. Here is the documentation for that (https://www.elastic.co/docs/solutions/search/the-search-api#track-total-hits). If we're computing a percentage, an estimated denominator would just lie to us. Forcing an exact count fixes that.

Running this end to end against `people`, pulling the declared fields, then checking coverage for each one:

![terminal output: declared fields and coverage percentages](/assets/images/25.png)

## Not hardcoding the stream

Everything above assumed a stream called `people`. In practice you don't know the stream names ahead of time, you ask Elasticsearch what exists:

```python
def list_streams(stream_pattern="*"):
    return [s["name"] for s in get("/_data_stream")["data_streams"]]
```

One call to `/_data_stream`, and you've got every stream name to loop over. Always the stream name, never the hidden `.ds-*` backing index underneath it. The stream name is the stable handle but the backing index rotates on its own.

## Q3b: what do the values actually look like?

Coverage tells you a field has data. It doesn't tell you *what's in it*. As a detection engineer you don't reason about a field in the abstract. You need to see it's actually `cmd.exe`, `powershell.exe`, `bash` before you can tell what's normal and what's an outlier.

```python
def top_values(stream, names):
    values = {}
    for chunk in chunks(names, BATCH):
        aggs = {str(i): {"terms": {"field": f, "size": 5}} for i, f in enumerate(chunk)}
        resp = post(f"/{stream}/_search", {"size": 0, "aggs": aggs})
        for i, f in enumerate(chunk):
            buckets = resp["aggregations"][str(i)]["buckets"]
            values[f] = {str(b["key"]): b["doc_count"] for b in buckets}
    return values
```

Same batching, same positional trick — just a `terms` aggregation instead of an `exists` filter. Worth noting: not every field type deserves this. Top-5 values of a timestamp or a float reading is noise, not signal — in practice you'd only run this for types like `keyword`, `ip`, `boolean`, and integer-ish fields, where "the 5 most common values" is actually a meaningful sentence.

```python
VALUE_TYPES = {"keyword", "ip", "boolean", "long", "integer", "short", "byte"}

wanted = [f for f in populated if declared[f] in VALUE_TYPES]
values = top_values(stream, wanted)
```

## The whole thing, end to end

Every piece above, wired together into one script:

```python
import json
import os

import requests

ES = os.environ.get("ES_URL", "http://localhost:9200")
BATCH = 50
VALUE_TYPES = {"keyword", "ip", "boolean", "long", "integer", "short", "byte"}


# ---------- plumbing ----------

def get(path, **kw):
    r = requests.get(ES + path, timeout=30, **kw)
    r.raise_for_status()
    return r.json()


def post(path, body):
    r = requests.post(ES + path, json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# ---------- the questions ----------

def list_streams():
    return [s["name"] for s in get("/_data_stream")["data_streams"]]


def existence(stream):
    total = post(f"/{stream}/_count", {})["count"]
    newest = None
    if total:
        resp = post(f"/{stream}/_search", {
            "size": 0,
            "aggs": {"newest": {"max": {"field": "@timestamp"}}},
        })
        newest = resp["aggregations"]["newest"].get("value_as_string")
    return total, newest


def declared_leaf_fields(stream):
    caps = get(f"/{stream}/_field_caps", params={"fields": "*"})["fields"]
    out = {}
    for name, types in caps.items():
        for tname, info in types.items():
            if info.get("metadata_field"):
                continue
            if tname in ("object", "nested"):
                continue
            if name.endswith(".text"):
                continue
            out[name] = tname
    return out


def coverage(stream, names):
    total = 0
    counts = {}
    for chunk in chunks(names, BATCH):
        aggs = {str(i): {"filter": {"exists": {"field": f}}} for i, f in enumerate(chunk)}
        resp = post(f"/{stream}/_search", {
            "size": 0,
            "track_total_hits": True,
            "aggs": aggs,
        })
        total = resp["hits"]["total"]["value"]
        for i, f in enumerate(chunk):
            counts[f] = resp["aggregations"][str(i)]["doc_count"]
    return total, counts


def top_values(stream, names):
    values = {}
    for chunk in chunks(names, BATCH):
        aggs = {str(i): {"terms": {"field": f, "size": 5}} for i, f in enumerate(chunk)}
        resp = post(f"/{stream}/_search", {"size": 0, "aggs": aggs})
        for i, f in enumerate(chunk):
            buckets = resp["aggregations"][str(i)]["buckets"]
            values[f] = {str(b["key"]): b["doc_count"] for b in buckets}
    return values


def sample_docs(stream, n=3):
    resp = post(f"/{stream}/_search", {
        "size": n,
        "query": {"function_score": {"random_score": {}}},
    })
    return [h["_source"] for h in resp["hits"]["hits"]]


# ---------- put it together ----------

def build_atlas():
    atlas = {}
    for stream in list_streams():
        docs, newest = existence(stream)
        if docs == 0:
            atlas[stream] = {"status": "DEAD", "docs": 0}
            continue

        declared = declared_leaf_fields(stream)
        total, counts = coverage(stream, list(declared))
        populated = {f: c for f, c in counts.items() if c > 0}
        wanted = [f for f in populated if declared[f] in VALUE_TYPES]
        values = top_values(stream, wanted)

        atlas[stream] = {
            "status": "ALIVE",
            "docs": docs,
            "newest": newest,
            "declared_fields": len(declared),
            "populated_fields": len(populated),
            "fields": {
                f: {"coverage_pct": round(100 * c / total, 1), "values": values.get(f)}
                for f, c in populated.items()
            },
            "samples": sample_docs(stream),
        }
    return atlas


if __name__ == "__main__":
    atlas = build_atlas()

    with open("atlas_test.json", "w") as f:
        json.dump(atlas, f, indent=2, default=str)

    for stream, e in atlas.items():
        if e["status"] == "DEAD":
            print(f"DEAD  {stream}")
        else:
            print(f"ALIVE {e['docs']:>6} docs  "
                  f"{e['populated_fields']:>4}/{e['declared_fields']:<5} fields populated  {stream}")

    print("\nDetail written to atlas_test.json")
```

Notice what's missing from the output on purpose: the hundreds of declared-but-empty fields never get listed one by one, only their *count* does. `top_values()` only runs against `populated`, never the full `declared` list. Every step narrows down to what's actually real, and only the real stuff survives into the JSON.

That's the whole thesis, landing in the output shape: mappings lie, but the data doesn't, so don't hand the agent the mapping, hand it the data.

```
uv run test-1.py
cat atlas_test.json | jq .
```
![final run output: script summary line plus jq'd atlas_test.json, showing process.parent.name filtered to values: null while process.parent.name.keyword gets real values](/assets/images/26.png)

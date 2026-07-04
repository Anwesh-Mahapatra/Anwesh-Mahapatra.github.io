---
layout: post
title: "Google Won't Give Us a Chronicle Free Tier, So I Built My Own YARA-L Engine"
date: 2026-07-04
categories: [Detection Engineering, Tooling]
tags: [detection-engineering, golang, yara-l, stream-processing]
author: Anwesh
---

You cannot run YARA-L 2.0 on your laptop. There is no local engine. So to test one correlation rule, you go to production.

## The Problem

Every other kind of code gets a unit test: run it locally, deterministic input, answer in milliseconds. Detections for Google SecOps get none of that. To check whether a windowed rule fires, you need:

- **A live tenant** — no tenant, no test.

- **Live API quotas** — every iteration burns against ingestion and rule limits.

- **Real latency** — upload, wait for ingestion, wait for scheduling, wait for the window to close. Minutes per attempt.

So the loop is: edit, upload, replay telemetry, wait, poll, guess. You can't put that in CI. You can't run a rule suite on a PR. You can't bisect which commit broke a detection.

People have asked Google for a local validator for years. The answer is silence. Fine.

## Correlant

**Correlant** is an independent, open-source YARA-L 2.0 engine in Go. No API wrapper, no phone-home — a **local, bounded-memory stream processor**. UDM-JSON in, detections out, offline, in milliseconds.

- **Hermetic** — a rule test is a Go test. Fixture in, detections out.

- **Bounded memory** — window state is keyed and evicted on watermark advance. Memory tracks the active window, not the corpus.

- **Spec-faithful, not prod-faithful** — it targets *documented* YARA-L semantics and writes down where Google diverges.

## The Architecture

Three stages: generate telemetry, normalize to UDM, run rules against it.

- **Generation** — [EvidenceForge](https://github.com/Cisco-Talos) for host telemetry; `genctl` for the cloud and IdP logs it doesn't cover. Both seeded, so the same call gives byte-identical output.

- **Normalization** — a Go normalizer maps raw provider records to UDM-JSON. Same mapping problem as prod, so fixtures exercise it too.

- **Engine** — hand-written lexer/parser → AST, then linter, single-event evaluator, and a correlation stage that windows on **event-time watermarks** with keyed state.

<figure class="arch-diagram">
  <div class="arch-toolbar">
    <button type="button" data-zoom="in" aria-label="Zoom in">+</button>
    <button type="button" data-zoom="out" aria-label="Zoom out">&minus;</button>
    <button type="button" data-zoom="reset" aria-label="Reset view">reset</button>
    <span class="arch-hint">drag to pan &middot; scroll to zoom</span>
  </div>
  <div class="arch-viewport">
    <svg viewBox="0 0 820 920" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Correlant pipeline architecture">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" class="arch-arrow"/>
        </marker>
      </defs>
      <g class="arch-pan">
        <!-- containers -->
        <rect x="40" y="24" width="420" height="120" rx="10" class="arch-group"/>
        <text x="60" y="48" class="arch-group-label">Data Generation</text>
        <rect x="110" y="418" width="520" height="410" rx="10" class="arch-group"/>
        <text x="130" y="442" class="arch-group-label">YARA-L Engine Core</text>

        <!-- edges -->
        <path d="M150,116 L245,200" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M350,116 L285,200" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M250,254 L175,308" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M170,366 L345,460" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M655,366 L425,460" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M380,512 L380,552" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M380,604 L380,644" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M380,696 L380,736" class="arch-edge" marker-end="url(#arrow)"/>
        <path d="M380,788 L380,846" class="arch-edge" marker-end="url(#arrow)"/>

        <!-- nodes -->
        <g class="arch-node">
          <rect x="70" y="68" width="160" height="48" rx="6"/>
          <text x="150" y="96">EvidenceForge</text>
        </g>
        <g class="arch-node">
          <rect x="270" y="68" width="160" height="48" rx="6"/>
          <text x="350" y="96">genctl: Cloud/IdP</text>
        </g>
        <g class="arch-node arch-accent">
          <rect x="150" y="200" width="200" height="54" rx="6"/>
          <text x="250" y="231">UDM Normalizer</text>
        </g>
        <g class="arch-node arch-store">
          <rect x="60" y="308" width="220" height="58" rx="6"/>
          <text x="170" y="342">UDM-JSON Fixtures</text>
        </g>
        <g class="arch-node arch-store">
          <rect x="545" y="308" width="220" height="58" rx="6"/>
          <text x="655" y="342">YARA-L Rule Repo</text>
        </g>
        <g class="arch-node">
          <rect x="250" y="462" width="260" height="50" rx="6"/>
          <text x="380" y="491">1 &middot; Lexer/Parser &rarr; AST</text>
        </g>
        <g class="arch-node">
          <rect x="250" y="554" width="260" height="50" rx="6"/>
          <text x="380" y="583">2 &middot; Linter &amp; Semantic Analyzer</text>
        </g>
        <g class="arch-node">
          <rect x="250" y="646" width="260" height="50" rx="6"/>
          <text x="380" y="675">3 &middot; Single-Event Evaluator</text>
        </g>
        <g class="arch-node">
          <rect x="250" y="738" width="260" height="50" rx="6"/>
          <text x="380" y="767">4 &middot; Correlation &amp; Windowing</text>
        </g>
        <g class="arch-node arch-out">
          <rect x="278" y="848" width="204" height="52" rx="26"/>
          <text x="380" y="879">Detection Output</text>
        </g>
      </g>
    </svg>
  </div>
</figure>

<style>
.arch-diagram{margin:2rem 0;border:1px solid var(--arch-line,#d0d5dd);border-radius:12px;overflow:hidden;background:var(--arch-bg,#fbfbfd)}
.arch-toolbar{display:flex;align-items:center;gap:.4rem;padding:.5rem .7rem;border-bottom:1px solid var(--arch-line,#d0d5dd);font-size:.8rem}
.arch-toolbar button{cursor:pointer;border:1px solid var(--arch-line,#d0d5dd);background:transparent;color:inherit;border-radius:6px;padding:.15rem .55rem;font:inherit;line-height:1.4}
.arch-toolbar button:hover{background:rgba(127,127,127,.12)}
.arch-hint{margin-left:auto;opacity:.55}
.arch-viewport{height:520px;overflow:hidden;cursor:grab;touch-action:none}
.arch-viewport:active{cursor:grabbing}
.arch-viewport svg{width:100%;height:100%;display:block}
.arch-group{fill:rgba(127,127,127,.05);stroke:var(--arch-line,#c4cbd6);stroke-dasharray:5 5}
.arch-group-label{fill:var(--arch-muted,#8a94a6);font:600 13px system-ui,sans-serif;letter-spacing:.02em}
.arch-node rect{fill:var(--arch-node,#fff);stroke:var(--arch-line,#c4cbd6);stroke-width:1.5}
.arch-node text{fill:var(--arch-text,#1f2430);font:500 14px system-ui,sans-serif;text-anchor:middle}
.arch-accent rect{fill:var(--arch-accent,#eef2ff);stroke:var(--arch-accent-line,#8ea2ff)}
.arch-store rect{fill:var(--arch-store,#f3f0ff);stroke:var(--arch-store-line,#b9a7f0)}
.arch-out rect{fill:var(--arch-out,#e9f9ef);stroke:var(--arch-out-line,#67c992)}
.arch-edge{fill:none;stroke:var(--arch-edge,#8a94a6);stroke-width:1.6}
.arch-arrow{fill:var(--arch-edge,#8a94a6)}
@media (prefers-color-scheme:dark){
  .arch-diagram{--arch-bg:#12151c;--arch-line:#2b313d;--arch-muted:#7a8494;--arch-node:#1b1f28;--arch-text:#e6e9ef;--arch-edge:#6b7688;--arch-accent:#1e2540;--arch-accent-line:#5468c9;--arch-store:#231d3a;--arch-store-line:#6f5bb0;--arch-out:#132a1f;--arch-out-line:#3f9a6b}
}
</style>

<script>
(function(){
  document.querySelectorAll('.arch-diagram').forEach(function(fig){
    var vp=fig.querySelector('.arch-viewport'),g=fig.querySelector('.arch-pan');
    var s=1,tx=0,ty=0,drag=false,px=0,py=0;
    function apply(){g.setAttribute('transform','translate('+tx+','+ty+') scale('+s+')');}
    function zoom(f,cx,cy){var r=vp.getBoundingClientRect();cx=cx==null?r.width/2:cx-r.left;cy=cy==null?r.height/2:cy-r.top;var ns=Math.min(4,Math.max(.4,s*f));tx=cx-(cx-tx)*(ns/s);ty=cy-(cy-ty)*(ns/s);s=ns;apply();}
    vp.addEventListener('wheel',function(e){e.preventDefault();zoom(e.deltaY<0?1.12:1/1.12,e.clientX,e.clientY);},{passive:false});
    vp.addEventListener('pointerdown',function(e){drag=true;px=e.clientX;py=e.clientY;vp.setPointerCapture(e.pointerId);});
    vp.addEventListener('pointermove',function(e){if(!drag)return;tx+=e.clientX-px;ty+=e.clientY-py;px=e.clientX;py=e.clientY;apply();});
    vp.addEventListener('pointerup',function(){drag=false;});
    fig.querySelectorAll('[data-zoom]').forEach(function(b){b.addEventListener('click',function(){var a=b.getAttribute('data-zoom');if(a==='in')zoom(1.25);else if(a==='out')zoom(1/1.25);else{s=1;tx=0;ty=0;apply();}});});
  });
})();
</script>

Watermarks and keyed state do the work. A correlation rule *is* a windowed keyed join — the local way to run one is the scaled way, minus the distribution.

## The Boundaries

Read this before using it for anything:

> **Limitations & Reality Check:** This project is an independent, lab-only execution engine for the YARA-L 2.0 specification. It successfully validates syntax against the public `chronicle/detection-rules` repository and executes windowed joins based on publicly documented language semantics. It does not—and cannot—replicate Google SecOps production behaviors. Divergences such as repeated-field unnesting mechanisms, detection deduplication, maximum sample-event limits, entity-graph enrichment dependencies, ingestion latency scaling, and retrohunt parallelization are strictly out of scope. Undocumented engine behaviors are cataloged in `DIVERGENCES.md`.

Passing the Correlant suite is necessary, not sufficient. It moves "this rule is obviously broken" from a production round trip to a local test. The "this hits an undocumented prod behavior" class stays in the tenant, where it always was.

## Next

The next post builds the part most people get wrong: a **lexer and AST in Go** that parses YARA-L *without regex*. Nested sections, placeholder variables, boolean trees, aggregation — none of it survives a regex. Token design, recursive descent, and the error messages that make local testing actually usable.

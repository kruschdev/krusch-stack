/**
 * @module docs/video/stage-template
 * @description Deterministic 1920x1080 HTML5/CSS3/SVG motion-graphics stage for KruschStack.
 * Driven frame-accurately via `window.__setVideoTime(tSeconds)` under headless Chromium.
 */

import {
  VIDEO_META,
  DEADBOLT_POLYGON_POINTS,
  PILLAR_CARDS,
  BENCHMARK_CARDS
} from './storyboard.js';

export function buildStageHtml(timeline) {
  const payloadJson = JSON.stringify({
    meta: VIDEO_META,
    deadboltPoints: DEADBOLT_POLYGON_POINTS,
    pillars: PILLAR_CARDS,
    benchmarks: BENCHMARK_CARDS,
    timeline
  });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${VIDEO_META.title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@500;600;700&family=Inter:wght@400;500;600;700&family=Outfit:wght@700;800;900&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body {
    width: 1920px;
    height: 1080px;
    overflow: hidden;
    background: #060911;
    color: #F4F7FB;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    -webkit-font-smoothing: antialiased;
    text-rendering: geometricPrecision;
  }

  .viewport {
    position: relative;
    width: 1920px;
    height: 1080px;
    background:
      radial-gradient(960px 540px at 14% 12%, rgba(0, 229, 255, 0.14), transparent 68%),
      radial-gradient(920px 560px at 86% 18%, rgba(139, 110, 255, 0.15), transparent 70%),
      radial-gradient(1100px 460px at 50% 96%, rgba(0, 245, 212, 0.09), transparent 72%),
      linear-gradient(180deg, #070B14 0%, #090E1B 52%, #050810 100%);
  }

  .cyber-grid {
    position: absolute;
    inset: -80px;
    background-image:
      linear-gradient(rgba(0, 229, 255, 0.045) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0, 229, 255, 0.045) 1px, transparent 1px);
    background-size: 56px 56px;
    mask-image: radial-gradient(ellipse at 50% 45%, rgba(0,0,0,0.92) 25%, rgba(0,0,0,0.22) 85%);
    pointer-events: none;
  }

  /* Top HUD (0..76px) */
  .hud-top {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 76px;
    padding: 0 72px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid rgba(148, 163, 184, 0.14);
    background: rgba(6, 9, 17, 0.74);
    backdrop-filter: blur(12px);
    z-index: 20;
  }

  .brand-lockup {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .brand-name {
    font-family: 'Outfit', sans-serif;
    font-weight: 800;
    font-size: 22px;
    letter-spacing: 0.04em;
    color: #F8FAFC;
  }

  .brand-version {
    font-family: 'Fira Code', monospace;
    font-size: 12px;
    font-weight: 600;
    color: #00E5FF;
    padding: 3px 9px;
    border-radius: 999px;
    background: rgba(0, 229, 255, 0.11);
    border: 1px solid rgba(0, 229, 255, 0.32);
  }

  .chapter-rail {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .chapter-pill {
    font-family: 'Fira Code', monospace;
    font-size: 11.5px;
    font-weight: 600;
    padding: 6px 12px;
    border-radius: 8px;
    color: rgba(203, 213, 225, 0.52);
    border: 1px solid rgba(148, 163, 184, 0.14);
    background: rgba(15, 23, 42, 0.45);
    letter-spacing: 0.04em;
  }

  .chapter-pill.active {
    color: #060911;
    background: linear-gradient(90deg, #00E5FF, #00F5D4);
    border-color: transparent;
    box-shadow: 0 0 18px rgba(0, 229, 255, 0.36);
    font-weight: 700;
  }

  .chapter-pill.done {
    color: #94A3B8;
    border-color: rgba(0, 229, 255, 0.25);
    background: rgba(0, 229, 255, 0.06);
  }

  .hud-right {
    display: flex;
    align-items: center;
    gap: 14px;
    font-family: 'Fira Code', monospace;
    font-size: 12.5px;
    color: #94A3B8;
  }

  .hud-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #00F5D4;
    box-shadow: 0 0 10px #00F5D4;
  }

  /* Scene Header (90..220px) */
  .scene-header {
    position: absolute;
    top: 92px;
    left: 72px;
    right: 72px;
    height: 126px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
    z-index: 10;
  }

  .scene-kicker {
    font-family: 'Fira Code', monospace;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.15em;
    color: #00E5FF;
    text-transform: uppercase;
  }

  .scene-headline {
    font-family: 'Outfit', sans-serif;
    font-weight: 800;
    font-size: 44px;
    line-height: 1.1;
    letter-spacing: -0.02em;
    background: linear-gradient(90deg, #FFFFFF 0%, #E2E8F0 65%, #7DD3FC 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }

  .scene-subhead {
    font-size: 18.5px;
    font-weight: 500;
    color: #94A3B8;
  }

  /* Main Stage (232..944px => 1776 x 712) */
  .stage-root {
    position: absolute;
    top: 232px;
    left: 72px;
    width: 1776px;
    height: 712px;
    z-index: 10;
  }

  /* Shared Glass Card */
  .glass-card {
    background: linear-gradient(180deg, rgba(15, 23, 42, 0.84) 0%, rgba(9, 14, 27, 0.90) 100%);
    border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 18px;
    box-shadow: 0 18px 42px rgba(0, 0, 0, 0.45);
  }

  /* Scene 1: Fragmented -> Unified */
  .s1-grid {
    display: grid;
    grid-template-columns: 790px 196px 790px;
    height: 712px;
    align-items: center;
  }

  .frag-list {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
  }

  .frag-item {
    padding: 16px 18px;
    border-radius: 14px;
    background: rgba(15, 23, 42, 0.78);
    border: 1px solid rgba(248, 113, 113, 0.30);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .frag-item.span2 {
    grid-column: span 2;
  }

  .frag-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .frag-repo {
    font-family: 'Fira Code', monospace;
    font-size: 14px;
    font-weight: 600;
    color: #E2E8F0;
  }

  .frag-warn {
    font-family: 'Fira Code', monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 6px;
    color: #FCA5A5;
    background: rgba(239, 68, 68, 0.14);
    border: 1px solid rgba(239, 68, 68, 0.32);
  }

  .frag-warn.unified {
    color: #00F5D4;
    background: rgba(0, 245, 212, 0.12);
    border-color: rgba(0, 245, 212, 0.35);
  }

  .frag-desc {
    font-size: 13.5px;
    color: #94A3B8;
  }

  .hero-monolith {
    height: 620px;
    padding: 40px 44px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    border-radius: 24px;
    background:
      radial-gradient(500px 300px at 50% 15%, rgba(0, 229, 255, 0.18), transparent 70%),
      linear-gradient(180deg, rgba(13, 21, 38, 0.95) 0%, rgba(7, 11, 22, 0.98) 100%);
    border: 1.5px solid rgba(0, 229, 255, 0.55);
    box-shadow: 0 0 60px rgba(0, 229, 255, 0.18), inset 0 1px 0 rgba(255,255,255,0.12);
  }

  .cmd-pill-lg {
    font-family: 'Fira Code', monospace;
    font-size: 24px;
    font-weight: 700;
    color: #00F5D4;
    background: rgba(4, 8, 16, 0.92);
    border: 1px solid rgba(0, 245, 212, 0.42);
    border-radius: 14px;
    padding: 18px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .stat-row-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
  }

  .mini-stat {
    padding: 16px;
    border-radius: 14px;
    background: rgba(15, 23, 42, 0.72);
    border: 1px solid rgba(148, 163, 184, 0.18);
    text-align: center;
  }

  .mini-stat-val {
    font-family: 'Outfit', sans-serif;
    font-weight: 800;
    font-size: 30px;
    color: #00E5FF;
  }

  .mini-stat-lbl {
    font-size: 12.5px;
    color: #94A3B8;
    margin-top: 3px;
  }

  /* Scene 2: Terminal + IDE Cards */
  .s2-grid {
    display: grid;
    grid-template-columns: 1110px 636px;
    gap: 30px;
    height: 696px;
  }

  .term-window {
    display: flex;
    flex-direction: column;
    border-radius: 18px;
    background: #050811;
    border: 1px solid rgba(0, 229, 255, 0.34);
    box-shadow: 0 24px 60px rgba(0,0,0,0.62);
    overflow: hidden;
  }

  .term-bar {
    height: 44px;
    padding: 0 18px;
    background: rgba(15, 23, 42, 0.92);
    border-bottom: 1px solid rgba(148, 163, 184, 0.15);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .term-dots {
    display: flex;
    gap: 8px;
  }

  .term-dots span {
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }

  .term-body {
    padding: 22px 26px;
    font-family: 'Fira Code', monospace;
    font-size: 15px;
    line-height: 1.56;
    color: #E2E8F0;
    flex: 1;
  }

  .ide-col {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .ide-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
  }

  .ide-card {
    padding: 18px 20px;
    border-radius: 14px;
    background: rgba(15, 23, 42, 0.80);
    border: 1px solid rgba(148, 163, 184, 0.18);
  }

  .ide-card.ready {
    border-color: rgba(0, 245, 212, 0.52);
    box-shadow: 0 0 24px rgba(0, 245, 212, 0.12);
  }

  /* Scene 3: 7 Pillars */
  .s3-wrap {
    display: flex;
    flex-direction: column;
    gap: 22px;
    height: 700px;
  }

  .pillars-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
    height: 518px;
  }

  .pillar-card {
    padding: 22px 24px;
    border-radius: 16px;
    background: rgba(12, 18, 34, 0.86);
    border: 1px solid rgba(148, 163, 184, 0.18);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .router-spine {
    height: 158px;
    padding: 20px 30px;
    border-radius: 18px;
    background: linear-gradient(90deg, rgba(13, 22, 42, 0.94), rgba(18, 16, 44, 0.94));
    border: 1.5px solid rgba(0, 229, 255, 0.44);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
  }

  .tier-hop {
    padding: 12px 18px;
    border-radius: 12px;
    background: rgba(6, 9, 17, 0.82);
    border: 1px solid rgba(0, 229, 255, 0.28);
    min-width: 195px;
  }

  /* Scene 4: Dual Harnesses */
  .s4-stack {
    display: flex;
    flex-direction: column;
    gap: 26px;
    height: 696px;
  }

  .harness-lane {
    flex: 1;
    padding: 26px 30px;
    border-radius: 20px;
    background: rgba(11, 17, 32, 0.88);
    border: 1px solid rgba(148, 163, 184, 0.22);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .stage-nodes {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 18px;
  }

  .stage-node {
    padding: 18px 20px;
    border-radius: 14px;
    background: rgba(6, 10, 20, 0.86);
    border: 1px solid rgba(148, 163, 184, 0.18);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  /* Scene 5: Benchmarks */
  .s5-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    grid-template-rows: 1fr 1fr;
    gap: 22px;
    height: 696px;
  }

  .bench-card {
    padding: 22px 28px;
    border-radius: 18px;
    background: rgba(11, 17, 32, 0.88);
    border: 1px solid rgba(148, 163, 184, 0.20);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .bar-track {
    width: 100%;
    height: 10px;
    border-radius: 999px;
    background: rgba(30, 41, 59, 0.85);
    overflow: hidden;
    margin-top: 4px;
  }

  .bar-fill {
    height: 100%;
    border-radius: 999px;
  }

  /* Scene 6: Outro */
  .s6-center {
    height: 696px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .outro-box {
    width: 1420px;
    padding: 48px 58px;
    border-radius: 26px;
    background:
      radial-gradient(720px 340px at 50% 0%, rgba(0, 229, 255, 0.18), transparent 72%),
      linear-gradient(180deg, rgba(13, 21, 38, 0.95) 0%, rgba(6, 10, 20, 0.98) 100%);
    border: 1.5px solid rgba(0, 229, 255, 0.52);
    box-shadow: 0 28px 80px rgba(0, 0, 0, 0.65);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 28px;
    text-align: center;
  }

  /* Lower-Third Broadcast Subtitle (958..1064px) */
  .caption-dock {
    position: absolute;
    bottom: 22px;
    left: 72px;
    right: 72px;
    height: 86px;
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    z-index: 30;
  }

  .caption-pill {
    max-width: 1580px;
    padding: 14px 30px;
    border-radius: 14px;
    background: rgba(5, 8, 16, 0.90);
    border: 1px solid rgba(0, 229, 255, 0.34);
    border-left: 4px solid #00E5FF;
    box-shadow: 0 12px 34px rgba(0, 0, 0, 0.65);
    font-size: 22.5px;
    font-weight: 500;
    line-height: 1.35;
    color: #F8FAFC;
    text-align: center;
  }

  .caption-pill code {
    font-family: 'Fira Code', monospace;
    font-size: 20px;
    font-weight: 600;
    color: #00F5D4;
    background: rgba(0, 245, 212, 0.11);
    padding: 2px 8px;
    border-radius: 6px;
  }

  /* Master Timeline Progress Bar */
  .progress-track {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 5px;
    background: rgba(30, 41, 59, 0.8);
    z-index: 40;
  }

  .progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #00E5FF 0%, #00F5D4 50%, #8B6EFF 100%);
    box-shadow: 0 0 14px rgba(0, 229, 255, 0.7);
  }
</style>
</head>
<body>
  <div class="viewport">
    <div class="cyber-grid" id="cyberGrid"></div>

    <header class="hud-top">
      <div class="brand-lockup">
        <svg viewBox="0 -2 132 218" width="24" height="39" aria-hidden="true">
          <defs>
            <linearGradient id="boltGradHud" x1="78%" y1="4%" x2="18%" y2="96%">
              <stop offset="0%" stop-color="#6ff1fe"/>
              <stop offset="35%" stop-color="#37e1ff"/>
              <stop offset="72%" stop-color="#8b6eff"/>
              <stop offset="100%" stop-color="#d946ef"/>
            </linearGradient>
          </defs>
          <polygon points="${DEADBOLT_POLYGON_POINTS}" fill="url(#boltGradHud)" stroke="#ffffff" stroke-width="3" stroke-linejoin="round" />
        </svg>
        <span class="brand-name">KRUSCH-STACK</span>
        <span class="brand-version">${VIDEO_META.version} · MIT</span>
      </div>

      <nav class="chapter-rail" id="chapterRail"></nav>

      <div class="hud-right">
        <span class="hud-dot"></span>
        <span>39 MCP TOOLS · NODE 22</span>
        <span id="timecodeText">00:00 / 00:00</span>
      </div>
    </header>

    <section class="scene-header" id="sceneHeader">
      <div class="scene-kicker" id="sceneKicker"></div>
      <h1 class="scene-headline" id="sceneHeadline"></h1>
      <p class="scene-subhead" id="sceneSubhead"></p>
    </section>

    <main class="stage-root" id="stageRoot"></main>

    <div class="caption-dock">
      <div class="caption-pill" id="captionPill"></div>
    </div>

    <div class="progress-track">
      <div class="progress-bar" id="progressBar" style="width:0%"></div>
    </div>
  </div>

<script>
const DATA = ${payloadJson};

function clamp(v, min = 0, max = 1) {
  return Math.max(min, Math.min(max, v));
}

function easeOutCubic(x) {
  const t = clamp(x);
  return 1 - Math.pow(1 - t, 3);
}

function easeInOutCubic(x) {
  const t = clamp(x);
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

function rangeProgress(p, start, end) {
  if (end <= start) return p >= end ? 1 : 0;
  return clamp((p - start) / (end - start));
}

function fmtClock(sec) {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return String(m).padStart(2, '0') + ':' + String(r).padStart(2, '0');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatCaptionMarkup(raw) {
  if (!raw) return '';
  const escaped = escapeHtml(raw);
  return escaped.replace(/\`([^\`]+)\`/g, '<code>$1</code>');
}

function deadboltSvg(width, height, idSuffix) {
  return \`<svg viewBox="0 -2 132 218" width="\${width}" height="\${height}" aria-hidden="true">
    <defs>
      <linearGradient id="bg-\${idSuffix}" x1="78%" y1="4%" x2="18%" y2="96%">
        <stop offset="0%" stop-color="#6ff1fe"/>
        <stop offset="30%" stop-color="#37e1ff"/>
        <stop offset="72%" stop-color="#8b6eff"/>
        <stop offset="100%" stop-color="#d946ef"/>
      </linearGradient>
    </defs>
    <polygon points="\${DATA.deadboltPoints}" fill="url(#bg-\${idSuffix})" stroke="#f8fafc" stroke-width="2.8" stroke-linejoin="round" />
  </svg>\`;
}

function renderSceneHook(p) {
  const unifyP = easeInOutCubic(rangeProgress(p, 0.42, 0.72));
  const items = [
    { repo: 'context-memory-mcp', warn: 'Context Amnesia', desc: 'Invariants & decisions vanish across sessions' },
    { repo: 'git-ast-indexer', warn: 'Blind Grep Sweeps', desc: 'Missing symbol spines & 2-hop call graphs' },
    { repo: 'os-page-reader', warn: 'Unbounded Reads', desc: 'Raw file dumps overflow context windows' },
    { repo: 'staged-2pc-harness', warn: 'Unguarded Writes', desc: 'Direct disk edits bypass policy floors' },
    { repo: 'turn0-grounding', warn: 'Spin-Loop Retries', desc: 'Repeated tool failures & schema traps' },
    { repo: 'frontend-design-mcp', warn: 'UI Boilerplate', desc: 'Hand-rolled shells & drifted CSS tokens' },
    { repo: 'workspace-rag + router', warn: '7 Separate Configs', desc: 'Manual wiring across Claude, Cursor & Windsurf', span2: true }
  ];

  const cardsHtml = items.map((it, idx) => {
    const enter = easeOutCubic(rangeProgress(p, idx * 0.04, idx * 0.04 + 0.16));
    const isUnified = unifyP > 0.55;
    const tx = (1 - enter) * -28 + unifyP * 10;
    const opacity = enter * (1 - unifyP * 0.25);
    return \`<div class="frag-item \${it.span2 ? 'span2' : ''}" style="opacity:\${opacity.toFixed(3)}; transform:translateX(\${tx.toFixed(1)}px); border-color:\${isUnified ? 'rgba(0,229,255,0.34)' : 'rgba(248,113,113,0.34)'}">
      <div class="frag-top">
        <span class="frag-repo">\${escapeHtml(it.repo)}</span>
        <span class="frag-warn \${isUnified ? 'unified' : ''}">\${isUnified ? 'UNIFIED ✓' : escapeHtml(it.warn)}</span>
      </div>
      <div class="frag-desc">\${escapeHtml(it.desc)}</div>
    </div>\`;
  }).join('');

  const heroEnter = easeOutCubic(rangeProgress(p, 0.36, 0.68));
  const heroScale = 0.94 + 0.06 * heroEnter;

  return \`<div class="s1-grid">
    <div class="frag-list">\${cardsHtml}</div>
    <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; gap:12px;">
      <svg width="170" height="240" viewBox="0 0 170 240">
        <defs>
          <linearGradient id="beamGrad" x1="0%" y1="50%" x2="100%" y2="50%">
            <stop offset="0%" stop-color="#f87171" stop-opacity="\${(0.65 - unifyP * 0.45).toFixed(2)}"/>
            <stop offset="50%" stop-color="#00e5ff" stop-opacity="\${(0.35 + unifyP * 0.65).toFixed(2)}"/>
            <stop offset="100%" stop-color="#00f5d4" stop-opacity="\${(0.25 + unifyP * 0.75).toFixed(2)}"/>
          </linearGradient>
        </defs>
        <path d="M 8 30 C 85 30, 85 120, 162 120" fill="none" stroke="url(#beamGrad)" stroke-width="3"/>
        <path d="M 8 85 C 85 85, 85 120, 162 120" fill="none" stroke="url(#beamGrad)" stroke-width="3"/>
        <path d="M 8 120 L 162 120" fill="none" stroke="url(#beamGrad)" stroke-width="4"/>
        <path d="M 8 155 C 85 155, 85 120, 162 120" fill="none" stroke="url(#beamGrad)" stroke-width="3"/>
        <path d="M 8 210 C 85 210, 85 120, 162 120" fill="none" stroke="url(#beamGrad)" stroke-width="3"/>
        <circle cx="\${(16 + unifyP * 138).toFixed(1)}" cy="120" r="7" fill="#00F5D4"/>
      </svg>
      <span style="font-family:'Fira Code',monospace; font-size:12px; color:#00E5FF; letter-spacing:0.12em;">\${unifyP > 0.5 ? '1 UNIFIED GATEWAY' : '7 FRAGMENTED SERVERS'}</span>
    </div>
    <div class="hero-monolith" style="opacity:\${(0.18 + 0.82 * heroEnter).toFixed(3)}; transform:scale(\${heroScale.toFixed(3)})">
      <div style="display:flex; align-items:center; justify-content:space-between;">
        <div style="display:flex; align-items:center; gap:18px;">
          \${deadboltSvg(46, 76, 's1')}
          <div>
            <div style="font-family:'Fira Code',monospace; font-size:13px; color:#00E5FF; letter-spacing:0.12em;">UNIFIED SOVEREIGN STACK</div>
            <div style="font-family:'Outfit',sans-serif; font-weight:900; font-size:40px; color:#FFFFFF;">KruschStack</div>
          </div>
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:13px; color:#00F5D4; padding:8px 14px; border-radius:10px; background:rgba(0,245,212,0.1); border:1px solid rgba(0,245,212,0.35);">ZERO SETUP</div>
      </div>

      <div class="cmd-pill-lg">
        <span><span style="color:#64748B;">$</span> npx krusch-stack init</span>
        <span style="font-size:13px; color:#94A3B8; font-weight:500;">Node 22 SQLite · Docker Optional</span>
      </div>

      <div style="font-size:17px; line-height:1.55; color:#CBD5E1;">
        Combines <strong>Working Memory</strong>, <strong>Git &amp; AST Call Graphs</strong>, <strong>OS Page Memory</strong>, <strong>Staged 2PC + Turn-0 Grounded Harnesses</strong>, <strong>Design Bricks</strong>, <strong>Workspace RAG</strong>, and a <strong>&lt;25µs Cascade Router</strong> behind one command.
      </div>

      <div class="stat-row-3">
        <div class="mini-stat">
          <div class="mini-stat-val">39</div>
          <div class="mini-stat-lbl">Annotated MCP Tools</div>
        </div>
        <div class="mini-stat">
          <div class="mini-stat-val" style="color:#00F5D4;">7</div>
          <div class="mini-stat-lbl">Sovereign Engines</div>
        </div>
        <div class="mini-stat">
          <div class="mini-stat-val" style="color:#A78BFA;">4 IDEs</div>
          <div class="mini-stat-lbl">Auto-Wired Instantly</div>
        </div>
      </div>
    </div>
  </div>\`;
}

function renderSceneCli(p) {
  const cmd1 = 'npx krusch-stack init';
  const typed1Len = Math.floor(cmd1.length * rangeProgress(p, 0.02, 0.15));
  const showInitOut = p >= 0.16;

  const cmd2 = 'npx krusch-stack doctor';
  const typed2Len = Math.floor(cmd2.length * rangeProgress(p, 0.34, 0.47));
  const showDocHeader = p >= 0.49;

  const pillarLines = [
    '[Tier 1]  krusch-context-mcp    — Working Memory & INV-12 Span Drift',
    '[Tier 2A] krusch-git            — AST Symbols, Call Graph & Search',
    '[Tier 2B] krusch-fs             — OS Structural Pages & PageMemory',
    '[Tier 3]  krusch-harness + gh   — 2PC Staged & Turn-0 Grounded Gates',
    '[Router]  krusch-cascade-router — <25µs L1-L3 Cognitive Cascade Router',
    '[Tier 4]  krusch-frontend-mcp   — Design Rules & 16 Lego Templates',
    '[Tier 5]  g-krusch              — Workspace Hub & Hybrid Document RAG'
  ];

  let termHtml = \`<div><span style="color:#00F5D4;">~/workspace/app</span> <span style="color:#00E5FF;">$</span> \${escapeHtml(cmd1.slice(0, typed1Len))}\${p < 0.16 ? '<span style="color:#00E5FF;">▋</span>' : ''}</div>\`;

  if (showInitOut) {
    termHtml += \`
      <div style="margin-top:8px; color:#38BDF8; font-weight:600;">🚀 KruschStack v1.1.0 initialized in ~/workspace/app</div>
      <div style="color:#94A3B8;">   Profile : <span style="color:#F8FAFC;">full (39 MCP tools)</span> · Mode: <span style="color:#F8FAFC;">unified</span></div>
      <div style="color:#94A3B8;">   Wired   : <span style="color:#00F5D4;">.mcp.json, .cursor/mcp.json, .windsurf/mcp_config.json, .antigravity/mcp_config.json</span></div>
      <div style="color:#94A3B8; margin-bottom:12px;">   SQLite  : <span style="color:#00F5D4;">READY (7 active engines · 0 Docker containers required)</span></div>
    \`;
  }

  if (p >= 0.33) {
    termHtml += \`<div><span style="color:#00F5D4;">~/workspace/app</span> <span style="color:#00E5FF;">$</span> \${escapeHtml(cmd2.slice(0, typed2Len))}\${p >= 0.33 && p < 0.49 ? '<span style="color:#00E5FF;">▋</span>' : ''}</div>\`;
  }

  if (showDocHeader) {
    termHtml += \`
      <div style="margin-top:8px; color:#F8FAFC; font-weight:600;">🩺 KruschStack Doctor (v1.1.0) — <span style="color:#00F5D4;">HEALTHY</span> <span style="color:#94A3B8; font-weight:400;">(Node v22.23 · SQLite=READY)</span></div>
    \`;
    pillarLines.forEach((line, idx) => {
      const appearAt = 0.48 + idx * 0.032;
      if (p >= appearAt) {
        termHtml += \`<div style="color:#CBD5E1;">  <span style="color:#00F5D4; font-weight:700;">✓</span> \${escapeHtml(line)}</div>\`;
      }
    });
  }

  const ides = [
    { name: 'Claude Code', file: '.mcp.json', readyAt: 0.19 },
    { name: 'Cursor IDE', file: '.cursor/mcp.json', readyAt: 0.22 },
    { name: 'Windsurf', file: '.windsurf/mcp_config.json', readyAt: 0.25 },
    { name: 'Antigravity', file: '.antigravity/mcp_config.json', readyAt: 0.28 }
  ];

  const deferP = easeOutCubic(rangeProgress(p, 0.56, 0.72));

  return \`<div class="s2-grid">
    <div class="term-window">
      <div class="term-bar">
        <div class="term-dots">
          <span style="background:#EF4444;"></span>
          <span style="background:#F59E0B;"></span>
          <span style="background:#10B981;"></span>
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:12.5px; color:#94A3B8;">zsh — ~/workspace/app — node v22 (node:sqlite)</div>
        <div style="font-family:'Fira Code',monospace; font-size:11.5px; color:#00F5D4;">STDIO + HTTP :3780</div>
      </div>
      <div class="term-body">\${termHtml}</div>
    </div>

    <div class="ide-col">
      <div class="glass-card" style="padding:24px;">
        <div style="font-family:'Fira Code',monospace; font-size:12px; color:#00E5FF; letter-spacing:0.12em; margin-bottom:14px;">AUTO-CONFIGURED MCP CLIENTS</div>
        <div class="ide-grid">
          \${ides.map((ide) => {
            const ready = p >= ide.readyAt;
            return \`<div class="ide-card \${ready ? 'ready' : ''}">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; font-size:16px; color:#F8FAFC;">\${ide.name}</span>
                <span style="font-family:'Fira Code',monospace; font-size:12px; color:\${ready ? '#00F5D4' : '#64748B'};">\${ready ? '● WIRED' : '○ WAIT'}</span>
              </div>
              <div style="font-family:'Fira Code',monospace; font-size:12.5px; color:#94A3B8; margin-top:6px;">\${ide.file}</div>
            </div>\`;
          }).join('')}
        </div>
      </div>

      <div class="glass-card" style="padding:26px; border-color:\${deferP > 0.2 ? 'rgba(167,139,250,0.52)' : 'rgba(148,163,184,0.18)'};">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span style="font-family:'Fira Code',monospace; font-size:12px; color:#A78BFA; letter-spacing:0.12em;">BM25 DEFERRED TOOL LOADING</span>
          <span style="font-family:'Fira Code',monospace; font-size:12px; color:#00F5D4;">--defer-tools</span>
        </div>
        <div style="font-family:'Outfit',sans-serif; font-weight:800; font-size:38px; color:#FFFFFF; margin-top:8px;">
          -\${(80.67 * deferP).toFixed(1)}% <span style="font-size:20px; font-weight:600; color:#CBD5E1;">Schema Tokens</span>
        </div>
        <div style="font-size:14.5px; color:#94A3B8; margin-top:6px; line-height:1.45;">
          Collapses wide MCP catalogs into <strong>6 pinned tools + 3 BM25 bridge tools</strong> (+6.40 pp on UC Berkeley BFCL v3 Live across 2,251 queries).
        </div>
        <div class="bar-track" style="margin-top:16px; height:12px;">
          <div class="bar-fill" style="width:\${(100 - 80.67 * deferP).toFixed(1)}%; background:linear-gradient(90deg, #A78BFA, #00F5D4);"></div>
        </div>
        <div style="display:flex; justify-content:space-between; font-family:'Fira Code',monospace; font-size:11.5px; color:#94A3B8; margin-top:6px;">
          <span>Active Prompt Footprint: \${(100 - 80.67 * deferP).toFixed(1)}%</span>
          <span>All 39 Tools Reachable</span>
        </div>
      </div>

      <div class="glass-card" style="padding:20px 24px; display:flex; align-items:center; justify-content:space-between;">
        <div>
          <div style="font-family:'Fira Code',monospace; font-size:12px; color:#38BDF8;">PRODUCTION DOCKER MODE</div>
          <div style="font-size:14.5px; color:#CBD5E1; margin-top:4px;">PostgreSQL 16 + <code style="color:#00F5D4; font-family:'Fira Code',monospace;">pgvector</code> HNSW</div>
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:14px; color:#00E5FF; padding:10px 14px; background:rgba(0,229,255,0.09); border:1px solid rgba(0,229,255,0.3); border-radius:10px;">docker compose up -d</div>
      </div>
    </div>
  </div>\`;
}

function renderScenePillars(p) {
  const cardsHtml = DATA.pillars.map((card, idx) => {
    const start = 0.03 + idx * 0.10;
    const enter = easeOutCubic(rangeProgress(p, start, start + 0.16));
    const active = p >= start && p < start + 0.18;
    return \`<div class="pillar-card" style="opacity:\${(0.22 + 0.78 * enter).toFixed(3)}; transform:translateY(\${((1 - enter) * 18).toFixed(1)}px); border-color:\${active ? card.accent : enter > 0.8 ? 'rgba(0,229,255,0.28)' : 'rgba(148,163,184,0.16)'}; box-shadow:\${active ? '0 0 28px ' + card.accent + '33' : 'none'};">
      <div>
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span style="font-family:'Fira Code',monospace; font-size:11.5px; font-weight:700; color:\${card.accent}; letter-spacing:0.1em;">\${escapeHtml(card.tier)}</span>
          <span style="font-family:'Fira Code',monospace; font-size:12px; color:#94A3B8;">\${escapeHtml(card.name)}</span>
        </div>
        <div style="font-family:'Outfit',sans-serif; font-weight:800; font-size:23px; color:#FFFFFF; margin-top:8px;">\${escapeHtml(card.title)}</div>
      </div>
      <ul style="list-style:none; display:flex; flex-direction:column; gap:7px; margin-top:12px;">
        \${card.bullets.map((b) => \`<li style="font-size:14px; color:#CBD5E1; display:flex; gap:8px;"><span style="color:\${card.accent}; font-weight:700;">›</span><span>\${escapeHtml(b)}</span></li>\`).join('')}
      </ul>
    </div>\`;
  }).join('');

  const routerEnter = easeOutCubic(rangeProgress(p, 0.66, 0.88));
  const hops = [
    { tier: 'STAGE 0 · <25µs', name: 'Pure-CPU Classifier', desc: 'Deterministic complexity & risk gate' },
    { tier: 'L1 / L2 · $0.00', name: 'Local Open-Weights', desc: '7B / 30B MoE / 31B Dense pool' },
    { tier: 'L2.5 · BURST', name: '120B High-VRAM Tier', desc: 'Deep synthesis & heavy audits' },
    { tier: 'L3 · FRONTIER', name: '3-Family Referee', desc: 'Cross-family convergence gate' }
  ];

  return \`<div class="s3-wrap">
    <div class="pillars-grid">\${cardsHtml}</div>
    <div class="router-spine" style="opacity:\${(0.3 + 0.7 * routerEnter).toFixed(3)}; box-shadow:\${routerEnter > 0.5 ? '0 0 36px rgba(0,229,255,0.22)' : 'none'};">
      <div style="min-width:340px;">
        <div style="font-family:'Fira Code',monospace; font-size:12px; color:#00F5D4; letter-spacing:0.12em;">PILLAR 7 · COGNITIVE CASCADE ROUTER</div>
        <div style="font-family:'Outfit',sans-serif; font-weight:800; font-size:26px; color:#FFFFFF; margin-top:4px;">&lt;25µs Stage-0 Task Dispatch</div>
        <div style="font-size:13.5px; color:#94A3B8; margin-top:3px;">Circuit-breaker fallback across local &amp; frontier tiers</div>
      </div>
      <div style="display:flex; align-items:center; gap:14px; flex:1; justify-content:flex-end;">
        \${hops.map((h, i) => \`
          <div class="tier-hop" style="border-color:\${routerEnter > i * 0.22 ? 'rgba(0,245,212,0.52)' : 'rgba(148,163,184,0.2)'}">
            <div style="font-family:'Fira Code',monospace; font-size:11px; color:#00E5FF; font-weight:700;">\${h.tier}</div>
            <div style="font-weight:700; font-size:15px; color:#F8FAFC; margin-top:4px;">\${h.name}</div>
            <div style="font-size:12px; color:#94A3B8; margin-top:2px;">\${h.desc}</div>
          </div>
          \${i < hops.length - 1 ? '<span style="color:#00E5FF; font-family:monospace; font-size:20px; font-weight:700;">→</span>' : ''}
        \`).join('')}
      </div>
    </div>
  </div>\`;
}

function renderSceneHarnesses(p) {
  const lane1Stages = [
    { step: '01 · INTROSPECT', title: '<150ms Schema Scan', body: 'Flags CSV "NA" traps, JSON null/[] wildcards & SQLite DDL at Turn 0 before any LLM call.' },
    { step: '02 · CALIBRATE', title: 'Scale-Aware Profile', body: 'Monotonic budgets for SMALL, MID & FRONTIER reasoning models without prompt bloat.' },
    { step: '03 · MEMOIZE', title: 'Spin-Loop Hash Guard', body: 'Normalized AST/snippet dedup + workspace mutation cache reset (-80% false blocks).' },
    { step: '04 · VERIFY STOP', title: 'Defect-Only Stop Gate', body: 'Blocks empty, NaN, truncated, or raw-XML tool leaks while preserving 0-turn clean stops.' }
  ];

  const lane2Stages = [
    { step: '01 · ISOLATE', title: 'Staged Workspace Diff', body: 'Mutations stage off-disk in SQLite/PG state machine; working tree stays untouched.' },
    { step: '02 · POLICY FLOOR', title: 'Import-Frozen Guard', body: 'Deterministic secret, SSRF, path-containment & prompt-injection floor (0/949 ASR).' },
    { step: '03 · AUDIT', title: 'INV-12 Span Nudge', body: 'Checks staged edits against pinned architectural invariants & symbol blast radius.' },
    { step: '04 · COMMIT', title: '<32ms Journal + Rename', body: 'Write-ahead apply intent journal + POSIX atomic renameSync/fsync with crash recovery.' }
  ];

  return \`<div class="s4-stack">
    <div class="harness-lane" style="border-color:rgba(0,229,255,0.42);">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-family:'Fira Code',monospace; font-size:12px; color:#00E5FF; letter-spacing:0.12em;">INV-STACK-11 · POST /grounded-harness/*</span>
          <h2 style="font-family:'Outfit',sans-serif; font-weight:800; font-size:28px; color:#FFFFFF; margin-top:2px;">Turn-0 Grounded, Scale-Aware Harness</h2>
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:13px; color:#00F5D4; padding:8px 14px; border-radius:10px; background:rgba(0,245,212,0.1); border:1px solid rgba(0,245,212,0.34);">
          Adyen DABstep: 90.0% (-74.5% Cost · 2.54x Faster)
        </div>
      </div>
      <div class="stage-nodes">
        \${lane1Stages.map((s, i) => {
          const on = easeOutCubic(rangeProgress(p, 0.03 + i * 0.10, 0.16 + i * 0.10));
          return \`<div class="stage-node" style="opacity:\${(0.25 + 0.75 * on).toFixed(3)}; border-color:\${on > 0.7 ? 'rgba(0,229,255,0.5)' : 'rgba(148,163,184,0.18)'};">
            <div style="font-family:'Fira Code',monospace; font-size:11.5px; color:#00E5FF; font-weight:700;">\${s.step}</div>
            <div style="font-family:'Outfit',sans-serif; font-weight:700; font-size:20px; color:#F8FAFC;">\${escapeHtml(s.title)}</div>
            <div style="font-size:13.5px; color:#94A3B8; line-height:1.45;">\${escapeHtml(s.body)}</div>
          </div>\`;
        }).join('')}
      </div>
    </div>

    <div class="harness-lane" style="border-color:rgba(167,139,250,0.45);">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-family:'Fira Code',monospace; font-size:12px; color:#A78BFA; letter-spacing:0.12em;">INV-STACK-10 · krusch-harness &amp; POST /action-harness/*</span>
          <h2 style="font-family:'Outfit',sans-serif; font-weight:800; font-size:28px; color:#FFFFFF; margin-top:2px;">Staged Two-Phase Commit (2PC) Execution Gate</h2>
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:13px; color:#A78BFA; padding:8px 14px; border-radius:10px; background:rgba(167,139,250,0.12); border:1px solid rgba(167,139,250,0.38);">
          -95.2% Duplicate MCP Calls · 70% Homelab Bench @ 9.1x Fewer Tokens
        </div>
      </div>
      <div class="stage-nodes">
        \${lane2Stages.map((s, i) => {
          const on = easeOutCubic(rangeProgress(p, 0.40 + i * 0.075, 0.52 + i * 0.075));
          return \`<div class="stage-node" style="opacity:\${(0.25 + 0.75 * on).toFixed(3)}; border-color:\${on > 0.7 ? 'rgba(167,139,250,0.55)' : 'rgba(148,163,184,0.18)'};">
            <div style="font-family:'Fira Code',monospace; font-size:11.5px; color:#A78BFA; font-weight:700;">\${s.step}</div>
            <div style="font-family:'Outfit',sans-serif; font-weight:700; font-size:20px; color:#F8FAFC;">\${escapeHtml(s.title)}</div>
            <div style="font-size:13.5px; color:#94A3B8; line-height:1.45;">\${escapeHtml(s.body)}</div>
          </div>\`;
        }).join('')}
      </div>
    </div>
  </div>\`;
}

function renderSceneBenchmarks(p) {
  const cardsHtml = DATA.benchmarks.map((b, idx) => {
    const start = 0.03 + idx * 0.18;
    const enter = easeOutCubic(rangeProgress(p, start, start + 0.22));
    return \`<div class="bench-card" style="opacity:\${(0.22 + 0.78 * enter).toFixed(3)}; transform:translateY(\${((1 - enter) * 14).toFixed(1)}px); border-color:\${enter > 0.75 ? b.badgeColor + '66' : 'rgba(148,163,184,0.2)'};">
      <div>
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
          <span style="font-weight:700; font-size:15.5px; color:#E2E8F0;">\${escapeHtml(b.suite)}</span>
          <span style="font-family:'Fira Code',monospace; font-size:10.5px; font-weight:700; color:\${b.badgeColor}; padding:4px 9px; border-radius:999px; background:rgba(15,23,42,0.9); border:1px solid \${b.badgeColor}66; white-space:nowrap;">\${escapeHtml(b.badge)}</span>
        </div>
        <div style="display:flex; align-items:baseline; gap:14px; margin-top:10px;">
          <span style="font-family:'Outfit',sans-serif; font-weight:900; font-size:46px; line-height:1; color:#FFFFFF;">\${escapeHtml(b.heroMetric)}</span>
          <span style="font-size:13.5px; color:#CBD5E1; font-weight:500;">\${escapeHtml(b.heroLabel)}</span>
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:12px; color:#94A3B8; margin-top:6px;">\${escapeHtml(b.subMetric)}</div>
      </div>

      <div style="display:flex; flex-direction:column; gap:9px; margin-top:12px;">
        \${b.bars.map((bar) => \`<div>
          <div style="display:flex; justify-content:space-between; font-size:12.5px; color:#CBD5E1;">
            <span>\${escapeHtml(bar.label)}</span>
            <span style="font-family:'Fira Code',monospace; font-weight:600;">\${bar.pct.toFixed(2)}%</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:\${(bar.pct * enter).toFixed(1)}%; background:\${bar.color};"></div>
          </div>
        </div>\`).join('')}
      </div>
    </div>\`;
  }).join('');

  return \`<div class="s5-grid">\${cardsHtml}</div>\`;
}

function renderSceneOutro(p) {
  const enter = easeOutCubic(rangeProgress(p, 0.0, 0.35));
  return \`<div class="s6-center">
    <div class="outro-box" style="opacity:\${enter.toFixed(3)}; transform:scale(\${(0.95 + 0.05 * enter).toFixed(3)});">
      <div style="display:flex; align-items:center; gap:22px;">
        \${deadboltSvg(68, 112, 'outro')}
        <div style="text-align:left;">
          <div style="font-family:'Fira Code',monospace; font-size:14px; color:#00E5FF; letter-spacing:0.16em;">UNIFIED SOVEREIGN AI &amp; CODING AGENT STACK</div>
          <div style="font-family:'Outfit',sans-serif; font-weight:900; font-size:64px; line-height:1.05; color:#FFFFFF;">KruschStack <span style="font-size:32px; color:#00F5D4;">\${DATA.meta.version}</span></div>
          <div style="font-size:20px; color:#94A3B8; margin-top:4px;">39 Annotated MCP Tools · Zero-LLM Raw-RAG · AST Graphs · 2PC &amp; Turn-0 Grounded Harnesses</div>
        </div>
      </div>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:22px; width:100%; margin-top:8px;">
        <div style="padding:22px 28px; border-radius:16px; background:#050811; border:1.5px solid rgba(0,245,212,0.5); text-align:left;">
          <div style="font-family:'Fira Code',monospace; font-size:12px; color:#00F5D4; letter-spacing:0.1em;">OPTION A · ZERO-DOCKER LOCAL (NODE &gt;= 22)</div>
          <div style="font-family:'Fira Code',monospace; font-size:24px; font-weight:700; color:#FFFFFF; margin-top:10px;"><span style="color:#00E5FF;">$</span> npx krusch-stack init</div>
          <div style="font-family:'Fira Code',monospace; font-size:16px; color:#94A3B8; margin-top:6px;"><span style="color:#00E5FF;">$</span> npx krusch-stack doctor</div>
        </div>
        <div style="padding:22px 28px; border-radius:16px; background:#050811; border:1.5px solid rgba(56,189,248,0.45); text-align:left;">
          <div style="font-family:'Fira Code',monospace; font-size:12px; color:#38BDF8; letter-spacing:0.1em;">OPTION B · FULL PGVECTOR + HTTP GATEWAY</div>
          <div style="font-family:'Fira Code',monospace; font-size:24px; font-weight:700; color:#FFFFFF; margin-top:10px;"><span style="color:#38BDF8;">$</span> docker compose up -d</div>
          <div style="font-family:'Fira Code',monospace; font-size:16px; color:#94A3B8; margin-top:6px;"><span style="color:#38BDF8;">$</span> curl http://127.0.0.1:3780/health</div>
        </div>
      </div>

      <div style="display:flex; align-items:center; justify-content:center; gap:24px; margin-top:6px;">
        <div style="font-family:'Fira Code',monospace; font-size:18px; font-weight:600; color:#F8FAFC; padding:12px 22px; border-radius:12px; background:rgba(0,229,255,0.12); border:1px solid rgba(0,229,255,0.4);">
          \${DATA.meta.repoUrl}
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:18px; font-weight:600; color:#00F5D4; padding:12px 22px; border-radius:12px; background:rgba(0,245,212,0.10); border:1px solid rgba(0,245,212,0.4);">
          https://\${DATA.meta.siteUrl}
        </div>
        <div style="font-family:'Fira Code',monospace; font-size:15px; color:#94A3B8; padding:12px 20px; border-radius:12px; background:rgba(15,23,42,0.8); border:1px solid rgba(148,163,184,0.22);">
          MIT License · 95/95 SHA-256 Gates
        </div>
      </div>
    </div>
  </div>\`;
}

const SCENE_RENDERERS = {
  hook: renderSceneHook,
  cli: renderSceneCli,
  pillars: renderScenePillars,
  harnesses: renderSceneHarnesses,
  benchmarks: renderSceneBenchmarks,
  outro: renderSceneOutro
};

window.__setVideoTime = function setVideoTime(tSec) {
  const total = DATA.timeline.totalDurationSec;
  const t = clamp(tSec, 0, total);

  // Subtle background grid drift
  const gridOffset = (t * 8) % 56;
  document.getElementById('cyberGrid').style.transform = \`translate3d(\${gridOffset.toFixed(2)}px, \${(gridOffset * 0.5).toFixed(2)}px, 0)\`;

  // Master progress & timecode
  document.getElementById('progressBar').style.width = \`\${((t / total) * 100).toFixed(3)}%\`;
  document.getElementById('timecodeText').textContent = \`\${fmtClock(t)} / \${fmtClock(total)}\`;

  // Locate active scene
  const scenes = DATA.timeline.scenes;
  let activeIdx = scenes.length - 1;
  for (let i = 0; i < scenes.length; i++) {
    if (t < scenes[i].endSec || i === scenes.length - 1) {
      activeIdx = i;
      break;
    }
  }
  const active = scenes[activeIdx];
  const localT = clamp(t - active.startSec, 0, active.durationSec);
  const p = active.durationSec > 0 ? localT / active.durationSec : 0;

  // Smooth cross-scene fade envelope (first 0.28s fade-in, last 0.22s fade-out except final hold)
  const fadeIn = easeOutCubic(clamp(localT / 0.28));
  const fadeOut = activeIdx < scenes.length - 1
    ? easeOutCubic(clamp((active.durationSec - localT) / 0.22))
    : 1;
  const envelope = Math.min(fadeIn, fadeOut);

  // Chapter rail
  document.getElementById('chapterRail').innerHTML = scenes.map((s, idx) => {
    const cls = idx === activeIdx ? 'active' : idx < activeIdx ? 'done' : '';
    return \`<span class="chapter-pill \${cls}">\${s.chapter} \${escapeHtml(s.navLabel)}</span>\`;
  }).join('');

  // Header
  const headerEl = document.getElementById('sceneHeader');
  headerEl.style.opacity = envelope.toFixed(3);
  headerEl.style.transform = \`translateY(\${((1 - fadeIn) * 10).toFixed(1)}px)\`;
  document.getElementById('sceneKicker').textContent = active.kicker;
  document.getElementById('sceneHeadline').textContent = active.headline;
  document.getElementById('sceneSubhead').textContent = active.subhead;

  // Stage
  const stageEl = document.getElementById('stageRoot');
  stageEl.style.opacity = envelope.toFixed(3);
  const renderer = SCENE_RENDERERS[active.id] || renderSceneHook;
  stageEl.innerHTML = renderer(p);

  // Active caption lookup
  const cap = DATA.timeline.captions.find((c) => t >= c.startSec && t <= c.endSec);
  const pill = document.getElementById('captionPill');
  if (cap) {
    const capFadeIn = easeOutCubic(clamp((t - cap.startSec) / 0.14));
    const capFadeOut = easeOutCubic(clamp((cap.endSec - t) / 0.14));
    pill.style.opacity = Math.min(capFadeIn, capFadeOut).toFixed(3);
    pill.innerHTML = formatCaptionMarkup(cap.text);
  } else {
    pill.style.opacity = '0';
    pill.innerHTML = '';
  }
};

window.__setVideoTime(0);
</script>
</body>
</html>`;
}

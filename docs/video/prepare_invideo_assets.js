#!/usr/bin/env node
/**
 * @module docs/video/prepare_invideo_assets
 * @description Prepares frame-accurate discrete multitrack assets (6 silent 1080p30 scene MP4
 * plates, 6 per-scene 24kHz VO WAVs, un-ducked stereo Dadd9 ambient pad WAV, and 2 procedural
 * tactile SFX WAVs) plus a timeline frame manifest for importing into an invideo timeline edit.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCENES, VIDEO_META } from './storyboard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CACHE_DIR = path.join(__dirname, '.cache');
const AUDIO_CACHE_DIR = path.join(CACHE_DIR, 'audio');
const OUT_DIR = path.join(CACHE_DIR, 'invideo-assets');
const SAMPLE_RATE = 24_000;

const SCENE_ASSET_SLUGS = Object.freeze({
  hook: '01_problem',
  cli: '02_cli',
  pillars: '03_pillars',
  harnesses: '04_harnesses',
  benchmarks: '05_benchmarks',
  outro: '06_outro'
});

async function loadToolkitAudio() {
  const localAudioUrl = new URL('../../../../lib/audio.js', import.meta.url);
  return import(localAudioUrl.href);
}

function buildAmbientPadWav(durationSec, encodeWavPcm16) {
  const frameCount = Math.ceil(durationSec * SAMPLE_RATE);
  const interleaved = new Float32Array(frameCount * 2);

  const voices = [
    { freq: 73.416, detune: 0.08, amp: 0.34, pan: 0.50 },
    { freq: 110.000, detune: -0.14, amp: 0.25, pan: 0.30 },
    { freq: 146.832, detune: 0.16, amp: 0.21, pan: 0.70 },
    { freq: 164.814, detune: -0.19, amp: 0.15, pan: 0.25 },
    { freq: 220.000, detune: 0.22, amp: 0.12, pan: 0.75 },
    { freq: 293.665, detune: -0.25, amp: 0.07, pan: 0.50 }
  ];

  // Clean -13.5 dBFS ceiling; timeline fades and sidechain ducking are applied live in invideo
  const masterGain = 0.21;
  const microEdgeSec = 0.04;

  for (let i = 0; i < frameCount; i++) {
    const t = i / SAMPLE_RATE;
    const breath = 0.86 + 0.14 * Math.sin(2 * Math.PI * 0.075 * t);
    const pulse = 0.93 + 0.07 * Math.sin(2 * Math.PI * 0.31 * t);

    let edge = 1.0;
    if (t < microEdgeSec) edge = t / microEdgeSec;
    else if (t > durationSec - microEdgeSec) edge = Math.max(0, (durationSec - t) / microEdgeSec);

    let left = 0;
    let right = 0;
    for (const v of voices) {
      const s1 = Math.sin(2 * Math.PI * v.freq * t);
      const s2 = Math.sin(2 * Math.PI * (v.freq + v.detune) * t + 0.7);
      const sig = 0.5 * (s1 + s2) * v.amp;
      left += sig * (1 - v.pan * 0.55);
      right += sig * (0.45 + v.pan * 0.55);
    }

    const g = masterGain * breath * pulse * edge;
    interleaved[i * 2] = Math.tanh(left * g * 1.15);
    interleaved[i * 2 + 1] = Math.tanh(right * g * 1.15);
  }

  return encodeWavPcm16(interleaved, { sampleRate: SAMPLE_RATE, channels: 2 });
}

function buildCutPulseLowWav(encodeWavPcm16) {
  const durationSec = 1.1; // 33 frames @ 30fps
  const frameCount = Math.round(durationSec * SAMPLE_RATE);
  const interleaved = new Float32Array(frameCount * 2);

  let phase1 = 0;
  let phase2 = 0;
  for (let i = 0; i < frameCount; i++) {
    const t = i / SAMPLE_RATE;
    // Exponential sub-bass sweep 112Hz -> 45Hz
    const f1 = 45 + 67 * Math.exp(-t * 9.5);
    const f2 = f1 * 2.0;
    phase1 += (2 * Math.PI * f1) / SAMPLE_RATE;
    phase2 += (2 * Math.PI * f2) / SAMPLE_RATE;

    const attack = t < 0.010 ? 0.5 * (1 - Math.cos((Math.PI * t) / 0.010)) : 1.0;
    const decay = Math.exp(-t * 4.6);
    const tailFade = t > durationSec - 0.08 ? Math.max(0, (durationSec - t) / 0.08) : 1.0;
    const env = attack * decay * tailFade;

    const body = (0.82 * Math.sin(phase1) + 0.18 * Math.sin(phase2)) * env * 0.42;
    interleaved[i * 2] = body;
    interleaved[i * 2 + 1] = body * 0.98;
  }

  return encodeWavPcm16(interleaved, { sampleRate: SAMPLE_RATE, channels: 2 });
}

function buildRevealShimmerWav(encodeWavPcm16) {
  const durationSec = 1.1; // 33 frames @ 30fps
  const frameCount = Math.round(durationSec * SAMPLE_RATE);
  const interleaved = new Float32Array(frameCount * 2);

  // Crystalline Dadd9 upper voicings (D5, F#5, A5, E6)
  const partials = [
    { freq: 587.33, delay: 0.00, decay: 3.4, amp: 0.34, pan: 0.36 },
    { freq: 739.99, delay: 0.03, decay: 3.8, amp: 0.26, pan: 0.64 },
    { freq: 880.00, delay: 0.06, decay: 4.1, amp: 0.22, pan: 0.28 },
    { freq: 1318.51, delay: 0.09, decay: 4.8, amp: 0.15, pan: 0.72 }
  ];

  for (let i = 0; i < frameCount; i++) {
    const t = i / SAMPLE_RATE;
    let left = 0;
    let right = 0;

    for (const p of partials) {
      if (t < p.delay) continue;
      const lt = t - p.delay;
      const att = lt < 0.018 ? 0.5 * (1 - Math.cos((Math.PI * lt) / 0.018)) : 1.0;
      const dec = Math.exp(-lt * p.decay);
      const sig = Math.sin(2 * Math.PI * p.freq * lt) * att * dec * p.amp;
      left += sig * (1 - p.pan * 0.5);
      right += sig * (0.5 + p.pan * 0.5);
    }

    const tail = t > durationSec - 0.08 ? Math.max(0, (durationSec - t) / 0.08) : 1.0;
    interleaved[i * 2] = left * tail * 0.48;
    interleaved[i * 2 + 1] = right * tail * 0.48;
  }

  return encodeWavPcm16(interleaved, { sampleRate: SAMPLE_RATE, channels: 2 });
}

async function main() {
  const audioBrick = await loadToolkitAudio();
  const timelinePath = path.join(CACHE_DIR, 'timeline.json');
  const masterMp4Path = path.join(__dirname, 'krusch-stack-tour.mp4');

  if (!fs.existsSync(timelinePath) || !fs.existsSync(masterMp4Path)) {
    throw new Error('Run generate_video.js first so timeline.json and krusch-stack-tour.mp4 exist.');
  }

  const timeline = JSON.parse(fs.readFileSync(timelinePath, 'utf8'));
  const fps = VIDEO_META.fps;
  const totalFrames = timeline.totalFrames;

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const cachedAudioFiles = fs.readdirSync(AUDIO_CACHE_DIR).filter((f) => f.endsWith('.wav'));

  const manifestScenes = [];

  for (let i = 0; i < timeline.scenes.length; i++) {
    const entry = timeline.scenes[i];
    const story = SCENES.find((s) => s.id === entry.id);
    const slug = SCENE_ASSET_SLUGS[entry.id];

    const startF = i === 0 ? 0 : Math.round(entry.startSec * fps);
    const endF = i === timeline.scenes.length - 1 ? totalFrames : Math.round(entry.endSec * fps);
    const durationF = endF - startF;

    const plateName = `scene_${slug}.mp4`;
    const platePath = path.join(OUT_DIR, plateName);

    console.log(`🎞️  Slicing ${plateName} [frames ${startF}..${endF} (${durationF}f)]...`);
    execFileSync(
      'ffmpeg',
      [
        '-y',
        '-i', masterMp4Path,
        '-an',
        '-vf', `trim=start_frame=${startF}:end_frame=${endF},setpts=PTS-STARTPTS`,
        '-r', String(fps),
        '-vsync', 'cfr',
        '-c:v', 'libx264',
        '-preset', 'medium',
        '-crf', '18',
        '-pix_fmt', 'yuv420p',
        '-movflags', '+faststart',
        platePath
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] }
    );

    const prefix = `${entry.chapter}-${entry.id}-`;
    const matchedWav = cachedAudioFiles.find((f) => f.startsWith(prefix));
    if (!matchedWav) {
      throw new Error(`Cached narration WAV not found for prefix ${prefix}`);
    }

    const voName = `vo_${slug}.wav`;
    const voPath = path.join(OUT_DIR, voName);
    fs.copyFileSync(path.join(AUDIO_CACHE_DIR, matchedWav), voPath);

    const parsedVo = audioBrick.parseWavHeader(new Uint8Array(fs.readFileSync(voPath)));
    const voDurationSec = parsedVo.data.durationSeconds;
    const voDurationF = Math.round(voDurationSec * fps);
    const prePadF = Math.round((story?.prePadSec ?? 0.3) * fps);
    const voStartF = startF + prePadF;

    manifestScenes.push({
      id: entry.id,
      chapter: entry.chapter,
      slug,
      navLabel: entry.navLabel,
      headline: entry.headline,
      plateFile: plateName,
      voFile: voName,
      startF,
      endF,
      durationF,
      voStartF,
      voDurationF,
      voEndF: voStartF + voDurationF,
      voDurationSec: Number(voDurationSec.toFixed(3))
    });
  }

  const totalDurationSec = totalFrames / fps;
  console.log(`🎹 Synthesizing music_cyber_ambient_pad.wav (${totalDurationSec.toFixed(2)}s) + 2 tactile SFX WAVs...`);
  fs.writeFileSync(
    path.join(OUT_DIR, 'music_cyber_ambient_pad.wav'),
    buildAmbientPadWav(totalDurationSec, audioBrick.encodeWavPcm16)
  );
  fs.writeFileSync(
    path.join(OUT_DIR, 'sfx_cut_pulse_low.wav'),
    buildCutPulseLowWav(audioBrick.encodeWavPcm16)
  );
  fs.writeFileSync(
    path.join(OUT_DIR, 'sfx_reveal_shimmer.wav'),
    buildRevealShimmerWav(audioBrick.encodeWavPcm16)
  );

  const manifest = {
    fps,
    width: VIDEO_META.width,
    height: VIDEO_META.height,
    totalFrames,
    totalDurationSec: Number(totalDurationSec.toFixed(3)),
    scenes: manifestScenes,
    musicFile: 'music_cyber_ambient_pad.wav',
    sfxFiles: {
      cutPulse: 'sfx_cut_pulse_low.wav',
      revealShimmer: 'sfx_reveal_shimmer.wav'
    }
  };

  const manifestPath = path.join(OUT_DIR, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log(`✅ Prepared 15 invideo assets in ${OUT_DIR}`);
}

main().catch((err) => {
  console.error('❌ Failed to prepare invideo assets:', err.message || err);
  process.exit(1);
});

#!/usr/bin/env node
/**
 * @module docs/video/generate_video
 * @description Reproducible, deterministic 1080p30 narrated video generator for KruschStack.
 *
 * Pipeline:
 *   1. Synthesizes per-scene 24kHz WAV narration via Kokoro-82M (`/v1/audio/speech` through
 *      `@krusch/toolkit/audio` `synthesizeSpeechAudio`) or `gemini-api tts` (`--tts gemini`),
 *      caching segments by SHA-256 content hash in `docs/video/.cache/audio/`.
 *   2. Parses exact sample-accurate WAV headers (`parseWavHeader`) and optionally audits spoken
 *      intelligibility via Whisper (`transcribeWhisperAudio`).
 *   3. Builds exact frame-locked scene + caption timelines (`krusch-stack-tour.srt`, `.vtt`, `timeline.json`).
 *   4. Synthesizes a stereo Dadd9 harmonic ambient pad (`encodeWavPcm16`) and mixes it beneath
 *      narration via FFmpeg `sidechaincompress` + EBU R128 `-16 LUFS` loudness normalization.
 *   5. Drives `stage-template.js` frame-by-frame (`window.__setVideoTime`) in headless Chromium
 *      and encodes `krusch-stack-tour.mp4` (H.264/AAC `+faststart`), `krusch-stack-tour.webm`
 *      (VP9/Opus), and `krusch-stack-poster.png`.
 */

import crypto from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { VIDEO_META, SCENES } from './storyboard.js';
import { buildStageHtml } from './stage-template.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CACHE_DIR = path.join(__dirname, '.cache');
const AUDIO_CACHE_DIR = path.join(CACHE_DIR, 'audio');
const KEYFRAMES_DIR = path.join(CACHE_DIR, 'keyframes');

const SAMPLE_RATE = 24_000;

async function loadToolkitAudio() {
  const localAudioUrl = new URL('../../../../lib/audio.js', import.meta.url);
  return import(localAudioUrl.href);
}

async function loadToolkitBrowser() {
  const localBrowserUrl = new URL('../../../../lib/browser.js', import.meta.url);
  return import(localBrowserUrl.href);
}

function parseCliFlags(argv = process.argv.slice(2)) {
  const opts = {
    tts: process.env.KRUSCH_VIDEO_TTS || 'auto',
    ttsEndpoint: process.env.KRUSCH_TTS_ENDPOINT || 'http://127.0.0.1:8880/v1/audio/speech',
    sttEndpoint: process.env.KRUSCH_STT_ENDPOINT || 'http://127.0.0.1:9000/v1/audio/transcriptions',
    voice: process.env.KRUSCH_VIDEO_VOICE || 'am_fenrir',
    geminiVoice: process.env.KRUSCH_GEMINI_VOICE || 'Charon',
    speed: Number(process.env.KRUSCH_VIDEO_SPEED || 1.16),
    workers: Number(process.env.KRUSCH_VIDEO_WORKERS || 4),
    verifyAsr: true,
    skipWebm: false,
    forceAudio: false
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--tts' && argv[i + 1]) opts.tts = argv[++i];
    else if (arg === '--voice' && argv[i + 1]) opts.voice = argv[++i];
    else if (arg === '--speed' && argv[i + 1]) opts.speed = Number(argv[++i]);
    else if (arg === '--no-verify-asr') opts.verifyAsr = false;
    else if (arg === '--skip-webm') opts.skipWebm = true;
    else if (arg === '--force-audio') opts.forceAudio = true;
  }
  return opts;
}

function formatSrtTimestamp(sec) {
  const totalMs = Math.max(0, Math.round(sec * 1000));
  const ms = totalMs % 1000;
  const totalSec = Math.floor(totalMs / 1000);
  const s = totalSec % 60;
  const totalMin = Math.floor(totalSec / 60);
  const m = totalMin % 60;
  const h = Math.floor(totalMin / 60);
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')},${String(ms).padStart(3, '0')}`;
}

function formatVttTimestamp(sec) {
  return formatSrtTimestamp(sec).replace(',', '.');
}

function stripBackticks(str) {
  return String(str).replace(/`([^`]+)`/g, '$1');
}

function extractMonoFloatSamples(wavBytes, header) {
  const view = new DataView(wavBytes.buffer, wavBytes.byteOffset, wavBytes.byteLength);
  const bytesPerSample = header.bitsPerSample / 8;
  const frameStride = header.channels * bytesPerSample;
  const frameCount = Math.floor(header.dataBytes / frameStride);
  const out = new Float32Array(frameCount);

  for (let i = 0; i < frameCount; i++) {
    const pos = header.dataOffset + i * frameStride;
    if (header.bitsPerSample === 16) {
      out[i] = view.getInt16(pos, true) / 32768;
    } else if (header.bitsPerSample === 32 && header.audioFormat === 3) {
      out[i] = view.getFloat32(pos, true);
    } else {
      out[i] = 0;
    }
  }
  return out;
}

function generateAmbientStereoPad(durationSec, sampleRate, encodeWavPcm16) {
  const frameCount = Math.ceil(durationSec * sampleRate);
  const interleaved = new Float32Array(frameCount * 2);

  // Warm Dadd9 ambient chord (low-mid register so speech range 1-4kHz remains crystal clear)
  const voices = [
    { freq: 73.416, detune: 0.08, amp: 0.34, pan: 0.50 },  // D2 sub root
    { freq: 110.000, detune: -0.14, amp: 0.24, pan: 0.32 }, // A2 fifth
    { freq: 146.832, detune: 0.16, amp: 0.20, pan: 0.68 },  // D3 octave
    { freq: 164.814, detune: -0.19, amp: 0.14, pan: 0.26 }, // E3 ninth
    { freq: 220.000, detune: 0.22, amp: 0.11, pan: 0.74 },  // A3 warm shimmer
    { freq: 293.665, detune: -0.25, amp: 0.06, pan: 0.50 }  // D4 soft air
  ];

  const fadeInSec = 1.6;
  const fadeOutSec = 2.4;
  const masterGain = 0.085; // ~ -21.4 dBFS peak before sidechain ducking

  for (let i = 0; i < frameCount; i++) {
    const t = i / sampleRate;
    const breath = 0.84 + 0.16 * Math.sin(2 * Math.PI * 0.075 * t);
    const pulse = 0.92 + 0.08 * Math.sin(2 * Math.PI * 0.33 * t);

    let env = 1.0;
    if (t < fadeInSec) {
      env = Math.pow(t / fadeInSec, 1.5);
    } else if (t > durationSec - fadeOutSec) {
      env = Math.pow(Math.max(0, (durationSec - t) / fadeOutSec), 1.6);
    }

    let left = 0;
    let right = 0;
    for (const v of voices) {
      const s1 = Math.sin(2 * Math.PI * v.freq * t);
      const s2 = Math.sin(2 * Math.PI * (v.freq + v.detune) * t + 0.7);
      const sig = 0.5 * (s1 + s2) * v.amp;
      left += sig * (1 - v.pan * 0.55);
      right += sig * (0.45 + v.pan * 0.55);
    }

    const gain = masterGain * breath * pulse * env;
    interleaved[i * 2] = Math.tanh(left * gain * 1.2);
    interleaved[i * 2 + 1] = Math.tanh(right * gain * 1.2);
  }

  return encodeWavPcm16(interleaved, { sampleRate, channels: 2 });
}

async function synthesizeSceneWav(scene, opts, audioBrick) {
  const hashKey = crypto
    .createHash('sha256')
    .update(JSON.stringify({ id: scene.id, text: scene.ttsText, tts: opts.tts, voice: opts.voice, speed: opts.speed }))
    .digest('hex')
    .slice(0, 14);

  const cachedPath = path.join(AUDIO_CACHE_DIR, `${scene.chapter}-${scene.id}-${hashKey}.wav`);
  if (!opts.forceAudio && fs.existsSync(cachedPath)) {
    return new Uint8Array(fs.readFileSync(cachedPath));
  }

  const tryKokoro = async () => {
    const res = await audioBrick.synthesizeSpeechAudio(scene.ttsText, {
      endpointUrl: opts.ttsEndpoint,
      voice: opts.voice,
      speed: opts.speed,
      responseFormat: 'wav',
      timeoutMs: 60_000
    });
    if (!res.ok) {
      throw new Error(`Kokoro TTS failed (${res.error.code}): ${res.error.message}`);
    }
    return res.data.audioBytes;
  };

  const tryGeminiCli = () => {
    const tmpWav = path.join(AUDIO_CACHE_DIR, `tmp-${scene.id}.wav`);
    execFileSync(
      'gemini-api',
      ['tts', scene.ttsText, '--voice', opts.geminiVoice, '--language', 'en-US', '--out', tmpWav],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    const raw = new Uint8Array(fs.readFileSync(tmpWav));
    fs.rmSync(tmpWav, { force: true });
    return raw;
  };

  let wavBytes;
  if (opts.tts === 'kokoro') {
    wavBytes = await tryKokoro();
  } else if (opts.tts === 'gemini') {
    wavBytes = tryGeminiCli();
  } else {
    try {
      wavBytes = await tryKokoro();
    } catch {
      wavBytes = tryGeminiCli();
    }
  }

  // Ensure canonical 24kHz mono PCM16 via ffmpeg if upstream sample rate differs
  const parsed = audioBrick.parseWavHeader(wavBytes);
  if (!parsed.ok || parsed.data.sampleRate !== SAMPLE_RATE || parsed.data.channels !== 1 || parsed.data.bitsPerSample !== 16) {
    const rawIn = path.join(AUDIO_CACHE_DIR, `raw-${scene.id}.wav`);
    fs.writeFileSync(rawIn, wavBytes);
    execFileSync('ffmpeg', ['-y', '-i', rawIn, '-ar', String(SAMPLE_RATE), '-ac', '1', '-c:a', 'pcm_s16le', cachedPath], {
      stdio: 'ignore'
    });
    fs.rmSync(rawIn, { force: true });
    return new Uint8Array(fs.readFileSync(cachedPath));
  }

  fs.writeFileSync(cachedPath, wavBytes);
  return wavBytes;
}

async function main() {
  const opts = parseCliFlags();
  fs.mkdirSync(AUDIO_CACHE_DIR, { recursive: true });
  fs.mkdirSync(KEYFRAMES_DIR, { recursive: true });

  const audioBrick = await loadToolkitAudio();
  const browserBrick = await loadToolkitBrowser();

  console.log('🎙️  Step 1/5 — Synthesizing & verifying scene narration...');
  const sceneEntries = [];
  const captionEntries = [];
  const masterChunks = [];
  let cursorSec = 0;

  for (const scene of SCENES) {
    const wavBytes = await synthesizeSceneWav(scene, opts, audioBrick);
    const parsed = audioBrick.parseWavHeader(wavBytes);
    if (!parsed.ok) {
      throw new Error(`Invalid WAV header for scene ${scene.id}: ${parsed.summary}`);
    }

    if (opts.verifyAsr) {
      const asr = await audioBrick.transcribeWhisperAudio(wavBytes, {
        endpointUrl: opts.sttEndpoint,
        filename: `${scene.id}.wav`,
        timeoutMs: 25_000
      });
      if (asr.ok) {
        console.log(`   ✓ [${scene.chapter} ${scene.id}] ${parsed.data.durationSeconds.toFixed(2)}s — ASR: "${asr.data.text.slice(0, 88)}..."`);
      } else {
        console.log(`   ✓ [${scene.chapter} ${scene.id}] ${parsed.data.durationSeconds.toFixed(2)}s (ASR skipped: ${asr.error.code})`);
      }
    } else {
      console.log(`   ✓ [${scene.chapter} ${scene.id}] ${parsed.data.durationSeconds.toFixed(2)}s`);
    }

    const speechSamples = extractMonoFloatSamples(wavBytes, parsed.data);
    const preSamples = new Float32Array(Math.round(scene.prePadSec * SAMPLE_RATE));
    const postSamples = new Float32Array(Math.round(scene.postPadSec * SAMPLE_RATE));

    const totalSceneSamples = preSamples.length + speechSamples.length + postSamples.length;
    const sceneDurationSec = totalSceneSamples / SAMPLE_RATE;
    const speechStartSec = cursorSec + preSamples.length / SAMPLE_RATE;
    const speechEndSec = speechStartSec + speechSamples.length / SAMPLE_RATE;

    masterChunks.push(preSamples, speechSamples, postSamples);

    // Proportional sub-caption timing across the spoken window
    const weights = scene.captions.map((c) => Math.max(8, stripBackticks(c).length));
    const totalWeight = weights.reduce((a, b) => a + b, 0);
    let capCursor = speechStartSec;
    const speechSpan = speechEndSec - speechStartSec;

    scene.captions.forEach((text, idx) => {
      const dur = (weights[idx] / totalWeight) * speechSpan;
      const startSec = capCursor;
      const endSec = idx === scene.captions.length - 1 ? speechEndSec + 0.18 : capCursor + dur - 0.04;
      captionEntries.push({
        index: captionEntries.length + 1,
        sceneId: scene.id,
        startSec: Number(startSec.toFixed(3)),
        endSec: Number(endSec.toFixed(3)),
        text,
        plainText: stripBackticks(text)
      });
      capCursor += dur;
    });

    sceneEntries.push({
      id: scene.id,
      chapter: scene.chapter,
      navLabel: scene.navLabel,
      kicker: scene.kicker,
      headline: scene.headline,
      subhead: scene.subhead,
      startSec: Number(cursorSec.toFixed(3)),
      endSec: Number((cursorSec + sceneDurationSec).toFixed(3)),
      durationSec: Number(sceneDurationSec.toFixed(3)),
      speechDurationSec: Number((speechSamples.length / SAMPLE_RATE).toFixed(3))
    });

    cursorSec += sceneDurationSec;
  }

  const totalDurationSec = Number(cursorSec.toFixed(3));
  const totalSamples = masterChunks.reduce((acc, arr) => acc + arr.length, 0);
  const fullVoiceSamples = new Float32Array(totalSamples);
  let sampleOffset = 0;
  for (const chunk of masterChunks) {
    fullVoiceSamples.set(chunk, sampleOffset);
    sampleOffset += chunk.length;
  }

  console.log(`🎼 Step 2/5 — Mixing master narration + Dadd9 ambient bed (${totalDurationSec.toFixed(2)}s)...`);
  const voiceMasterPath = path.join(CACHE_DIR, 'voiceover-master.wav');
  const ambientPadPath = path.join(CACHE_DIR, 'ambient-pad.wav');
  const mixedAudioPath = path.join(CACHE_DIR, 'master-mix.wav');

  fs.writeFileSync(voiceMasterPath, audioBrick.encodeWavPcm16(fullVoiceSamples, { sampleRate: SAMPLE_RATE, channels: 1 }));
  fs.writeFileSync(ambientPadPath, generateAmbientStereoPad(totalDurationSec, SAMPLE_RATE, audioBrick.encodeWavPcm16));

  execFileSync(
    'ffmpeg',
    [
      '-y',
      '-i', voiceMasterPath,
      '-i', ambientPadPath,
      '-filter_complex',
      '[0:a]highpass=f=75,pan=stereo|c0=c0|c1=c0,asplit=2[vo][sc];' +
        '[1:a][sc]sidechaincompress=threshold=0.025:ratio=5:attack=18:release=620[bg];' +
        '[vo][bg]amix=inputs=2:duration=first:dropout_transition=0:weights=1.0 0.32,' +
        'loudnorm=I=-16:TP=-1.5:LRA=11[out]',
      '-map', '[out]',
      '-ar', '48000',
      '-c:a', 'pcm_s16le',
      mixedAudioPath
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] }
  );

  console.log('📝 Step 3/5 — Writing synchronized SRT, WebVTT & timeline manifest...');
  const srtPath = path.join(__dirname, 'krusch-stack-tour.srt');
  const vttPath = path.join(__dirname, 'krusch-stack-tour.vtt');
  const timelinePath = path.join(CACHE_DIR, 'timeline.json');

  const srtContent = captionEntries
    .map((c) => `${c.index}\n${formatSrtTimestamp(c.startSec)} --> ${formatSrtTimestamp(c.endSec)}\n${c.plainText}\n`)
    .join('\n');
  const vttContent =
    'WEBVTT\n\n' +
    captionEntries
      .map((c) => `${c.index}\n${formatVttTimestamp(c.startSec)} --> ${formatVttTimestamp(c.endSec)}\n${c.plainText}\n`)
      .join('\n');

  fs.writeFileSync(srtPath, srtContent, 'utf8');
  fs.writeFileSync(vttPath, vttContent, 'utf8');

  const timeline = {
    meta: VIDEO_META,
    totalDurationSec,
    totalFrames: Math.ceil(totalDurationSec * VIDEO_META.fps),
    scenes: sceneEntries,
    captions: captionEntries
  };
  fs.writeFileSync(timelinePath, JSON.stringify(timeline, null, 2), 'utf8');

  const stageHtmlPath = path.join(CACHE_DIR, 'stage.html');
  fs.writeFileSync(stageHtmlPath, buildStageHtml(timeline), 'utf8');

  console.log(`🎬 Step 4/5 — Rendering ${timeline.totalFrames} frames @ ${VIDEO_META.width}x${VIDEO_META.height} (${VIDEO_META.fps}fps)...`);
  const mp4Path = path.join(__dirname, 'krusch-stack-tour.mp4');
  const posterPath = path.join(__dirname, 'krusch-stack-poster.png');

  const browser = await browserBrick.launchBrowser({
    viewport: { width: VIDEO_META.width, height: VIDEO_META.height, deviceScaleFactor: 1 }
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: VIDEO_META.width, height: VIDEO_META.height, deviceScaleFactor: 1 });
    await page.goto(pathToFileURL(stageHtmlPath).href, { waitUntil: 'networkidle0', timeout: 30_000 });
    await page.evaluate(() => document.fonts.ready);

    // Capture 6 diagnostic keyframes + poster image first
    for (const s of sceneEntries) {
      const sampleSec = s.startSec + s.durationSec * 0.72;
      await page.evaluate((t) => window.__setVideoTime(t), sampleSec);
      const kfPath = path.join(KEYFRAMES_DIR, `scene-${s.chapter}-${s.id}.png`);
      await page.screenshot({ path: kfPath, type: 'png' });
      if (s.id === 'hook') {
        fs.copyFileSync(kfPath, posterPath);
      }
    }

    // Stream frames directly into FFmpeg H.264 + AAC
    const ffmpegProc = spawn(
      'ffmpeg',
      [
        '-y',
        '-f', 'image2pipe',
        '-vcodec', 'mjpeg',
        '-framerate', String(VIDEO_META.fps),
        '-i', '-',
        '-i', mixedAudioPath,
        '-map', '0:v:0',
        '-map', '1:a:0',
        '-c:v', 'libx264',
        '-preset', 'medium',
        '-crf', '20',
        '-pix_fmt', 'yuv420p',
        '-c:a', 'aac',
        '-b:a', '192k',
        '-movflags', '+faststart',
        '-shortest',
        mp4Path
      ],
      { stdio: ['pipe', 'ignore', 'pipe'] }
    );

    let ffErr = '';
    ffmpegProc.stderr.on('data', (d) => {
      ffErr += d.toString();
      if (ffErr.length > 8192) ffErr = ffErr.slice(-8192);
    });

    const exitPromise = new Promise((resolve, reject) => {
      ffmpegProc.on('error', reject);
      ffmpegProc.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`FFmpeg MP4 encode failed (${code}):\n${ffErr}`));
      });
    });

    // Parallel multi-page frame capture (strictly ordered batch flush into ffmpeg.stdin)
    const workerCount = Math.max(1, Math.min(6, opts.workers || 4));
    const pages = [page];
    for (let w = 1; w < workerCount; w++) {
      const p = await browser.newPage();
      await p.setViewport({ width: VIDEO_META.width, height: VIDEO_META.height, deviceScaleFactor: 1 });
      await p.goto(pathToFileURL(stageHtmlPath).href, { waitUntil: 'networkidle0', timeout: 30_000 });
      await p.evaluate(() => document.fonts.ready);
      pages.push(p);
    }

    for (let base = 0; base < timeline.totalFrames; base += workerCount) {
      const batchSize = Math.min(workerCount, timeline.totalFrames - base);
      const buffers = await Promise.all(
        Array.from({ length: batchSize }, async (_, offset) => {
          const frameIdx = base + offset;
          const workerPage = pages[offset];
          await workerPage.evaluate((t) => window.__setVideoTime(t), frameIdx / VIDEO_META.fps);
          return workerPage.screenshot({ type: 'jpeg', quality: 95, encoding: 'binary' });
        })
      );

      for (const jpegBuf of buffers) {
        const canContinue = ffmpegProc.stdin.write(jpegBuf);
        if (!canContinue) {
          await new Promise((r) => ffmpegProc.stdin.once('drain', r));
        }
      }

      const doneFrame = base + batchSize;
      if (doneFrame % 300 < workerCount || doneFrame === timeline.totalFrames) {
        console.log(`   → Rendered frame ${doneFrame} / ${timeline.totalFrames} (${((doneFrame / timeline.totalFrames) * 100).toFixed(1)}%)`);
      }
    }

    ffmpegProc.stdin.end();
    await exitPromise;
    for (const p of pages) {
      await p.close();
    }
  } finally {
    await browser.close();
  }

  if (!opts.skipWebm) {
    console.log('🌐 Step 5/5 — Transcoding WebM (VP9 + Opus) companion stream...');
    const webmPath = path.join(__dirname, 'krusch-stack-tour.webm');
    execFileSync(
      'ffmpeg',
      [
        '-y',
        '-i', mp4Path,
        '-c:v', 'libvpx-vp9',
        '-crf', '26',
        '-b:v', '0',
        '-deadline', 'good',
        '-cpu-used', '3',
        '-row-mt', '1',
        '-c:a', 'libopus',
        '-b:a', '160k',
        webmPath
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] }
    );
  }

  console.log(`✅ Video build complete! Output: ${mp4Path}`);
}

main().catch((err) => {
  console.error('❌ Video generation failed:', err.message || err);
  process.exit(1);
});

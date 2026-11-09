# KruschStack Narrated Product Tour (`docs/video/`)

Deterministic, frame-locked `1920x1080` (`30fps`) narrated product tour for **KruschStack (`krusch-stack`)**.

## Generated Assets

| File | Format | Purpose |
|------|--------|---------|
| [`krusch-stack-tour.mp4`](./krusch-stack-tour.mp4) | H.264 (`yuv420p`, CRF 20) + AAC (`192k`, `+faststart`) | Universal GitHub README, X/Twitter, LinkedIn & Safari/Chrome video |
| [`krusch-stack-tour.webm`](./krusch-stack-tour.webm) | VP9 + Opus (`160k`) | Compact high-clarity web stream for `krusch.dev` `<video>` embeds |
| [`krusch-stack-tour.srt`](./krusch-stack-tour.srt) | SubRip (`.srt`) | Time-aligned closed captions |
| [`krusch-stack-tour.vtt`](./krusch-stack-tour.vtt) | WebVTT (`.vtt`) | HTML5 `<track kind="captions">` subtitle track |
| [`krusch-stack-poster.png`](./krusch-stack-poster.png) | `1920x1080` PNG | High-contrast poster frame |

## Rebuilding Locally

```bash
# Default: auto-detects local Kokoro-82M (/v1/audio/speech on :8880) or falls back to gemini-api tts
node docs/video/generate_video.js

# Force Gemini Cloud TTS (when AI Studio credits are active)
node docs/video/generate_video.js --tts gemini --force-audio

# Customize Kokoro voice or playback rate
node docs/video/generate_video.js --tts kokoro --voice "am_fenrir" --speed 1.16

# Slice 6 discrete 1080p30 scene plates + 24kHz VO/music/SFX WAV stems for invideo multitrack editing
node docs/video/prepare_invideo_assets.js
```

## Architecture of the Video Pipeline

1. **[`storyboard.js`](./storyboard.js)** — Authoritative 6-scene script, phonetic TTS prompts, synchronized caption cues, and verified benchmark telemetry (`INV-SOLO-VOICE-01` & `INV-LEGO-26` compliant).
2. **[`stage-template.js`](./stage-template.js)** — Self-contained `1920x1080` HTML5/CSS3/SVG motion-graphics stage driven deterministically via `window.__setVideoTime(tSeconds)` (zero wall-clock frame jitter).
3. **[`generate_video.js`](./generate_video.js)** — Uses `@krusch/toolkit/audio` (`synthesizeSpeechAudio`, `parseWavHeader`, `encodeWavPcm16`, `transcribeWhisperAudio`) + `@krusch/toolkit/browser` (`launchBrowser`) + `ffmpeg` (`sidechaincompress` ducking over a stereo `Dadd9` ambient pad + EBU R128 `-16 LUFS` loudness normalization).
4. **[`prepare_invideo_assets.js`](./prepare_invideo_assets.js)** — Exports frame-exact silent `1080p30` scene plates (`scene_01_problem.mp4`..`scene_06_outro.mp4`), discrete `24kHz` narration stems (`vo_01`..`vo_06`), un-ducked stereo `Dadd9` pad (`music_cyber_ambient_pad.wav`), and procedural tactile SFX (`sfx_cut_pulse_low.wav`, `sfx_reveal_shimmer.wav`) for non-destructive multitrack assembly in `invideo`.

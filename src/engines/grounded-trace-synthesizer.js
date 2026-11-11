/**
 * @module engines/grounded-trace-synthesizer
 * Meta-Harness Failure-Trace Miner, Teacher Rule Synthesizer, and Holdout Replay
 * Verifier (INV-GH-11, inspired by EmoHarness arXiv:2611.11994 & Infrathon arXiv:2611.11995).
 *
 * Implements a 3-stage closed loop with zero external dependencies (INV-STACK-01):
 * 1. Stage A (`mineFailureTrajectories`): Deterministic zero-LLM failure taxonomy & command mining
 *    across benchmark result JSONL files and step-by-step `.traj.json` / `grounded_events` logs.
 * 2. Stage B (`synthesizeRulesWithTeacher`): Optional Teacher LLM rule proposal via injectable
 *    `chatJsonFn` or local OpenAI-compatible HTTP endpoint (`AbortSignal.timeout`).
 * 3. Stage C (`verifyCandidateRulesOnTraces`): Deterministic holdout replay gate rejecting any
 *    candidate rule with invalid/ReDoS regexes, policy-floor subversion, or `falsePositiveHits > 0`
 *    against clean passing trajectories and canonical safe commands.
 */

import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

export const SYNTHESIZED_RULE_ACTIONS = Object.freeze({
  HOLD_PSEUDO_COMPLETION_LOOP: 'HOLD_PSEUDO_COMPLETION_LOOP',
  EXEMPT_DUPLICATE_WRITE: 'EXEMPT_DUPLICATE_WRITE',
  EXEMPT_CLEANUP_DIFF: 'EXEMPT_CLEANUP_DIFF',
  CREDIT_INLINE_VERIFY: 'CREDIT_INLINE_VERIFY',
  HOLD_TOOL_PATTERN: 'HOLD_TOOL_PATTERN'
});

const VALID_RULE_ACTIONS = new Set(Object.values(SYNTHESIZED_RULE_ACTIONS));

const TRIVIAL_REGEX_PATTERNS = new Set([
  '.*',
  '.+',
  '^.*$',
  '^.+$',
  '[\\s\\S]*',
  '[\\s\\S]+'
]);

const NESTED_QUANTIFIER_RE = /\([^()\\]*(?:\+|\*|\{\d+,?\d*\})[^()\\]*\)\s*(?:\+|\*|\{\d+,?\d*\})/;

const DESTRUCTIVE_FLOOR_RE =
  /(?:\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+\/(?:\s|["';|&)]|$)|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+push\s+--force\b|\bDROP\s+DATABASE\b|\bcat\s+\.env\b)/i;

const CANONICAL_CLEAN_COMMANDS = Object.freeze([
  'echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT',
  'echo "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" && git diff',
  'pytest -q',
  'python3 -m pytest tests/test_core.py',
  'node --test tests/*.test.js',
  'npm test',
  'git status -sb',
  'git diff HEAD',
  'sed -n "1,80p" src/index.js',
  'rg -n "parseAIJson" .',
  'python3 -c "import pathlib; p = pathlib.Path(\'app.py\'); print(len(p.read_text()))"',
  'echo "fixture_line" > /tmp/fixture_input.txt'
]);

const FORBIDDEN_EXEMPT_PROBES = Object.freeze([
  'rm -rf /',
  'git reset --hard HEAD~1',
  'git clean -fdx',
  'git push --force origin main',
  'cat .env'
]);

/**
 * Empirically grounded default Meta-Harness rules distilled from coding harness
 * trajectory corpora (`0` false positives across clean passing episodes).
 */
export const DEFAULT_EVOLVED_HARNESS_RULES = Object.freeze([
  Object.freeze({
    id: 'GH-EVO-01',
    action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_DUPLICATE_WRITE,
    toolPattern: '^(?:bash|sh|shell|run_command|run_shell|exec)$',
    commandRegex:
      '^\\s*(?:cd\\s+\\S+\\s*&&\\s*)?git\\s+(?:checkout\\s+(?:HEAD\\s+)?--\\s+\\S+|restore\\s+(?!--staged\\s*$)\\S+)\\s*$',
    targetFailureMode: 'IDEMPOTENT_ROLLBACK_BLOCKED',
    rationale:
      'Allow idempotent single-file git checkout/restore rollbacks (including cd <dir> && prefixes) after botched edits without triggering BLOCK_DUPLICATE_WRITE.'
  }),
  Object.freeze({
    id: 'GH-EVO-02',
    action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF,
    toolPattern: '^(?:bash|sh|shell|run_command|run_shell|exec)$',
    commandRegex:
      '^\\s*(?:cd\\s+\\S+\\s*&&\\s*)?rm\\s+(?:-[rfv]+\\s+)*(?![^\\n]*\\btests?\\/)(?:(?:/tmp/|\\./)?(?:test[_-][\\w.-]+|[\\w.-]+[_-]test\\.[A-Za-z0-9]+|verify[_-]?[\\w.-]*\\.(?:m?js|cjs|py)|simple_test\\.[A-Za-z0-9]+|[\\w.-]+\\.(?:bak|orig|tmp))(?:\\s+|$))+$',
    targetFailureMode: 'TEMP_CLEANUP_FALSE_DIFF',
    rationale:
      'Prevent temporary scratch/test file cleanup (rm -f test_*.js verify.mjs *.bak, never inside test/ or tests/) after passing tests from dirtying pending_diffs_count right before submission.'
  }),
  Object.freeze({
    id: 'GH-EVO-03',
    action: SYNTHESIZED_RULE_ACTIONS.CREDIT_INLINE_VERIFY,
    toolPattern: '^(?:bash|sh|shell|run_command|run_shell|exec)$',
    commandRegex:
      '(?:\\b(?:pytest|py\\.test|tox|runtests|jest|vitest)\\b|\\bpython3?\\s+-m\\s+(?:pytest|unittest)\\b|\\bnode\\s+--test\\b|\\bnpm\\s+(?:run\\s+)?test\\b|^\\s*(?:cd\\s+\\S+\\s*&&\\s*)?(?:node|python3?)\\s+(?:-[ec]\\s+|(?:/tmp/|\\./)?(?:test[_-][\\w.-]+|verify[_-]?[\\w.-]*|simple_test\\.[\\w.-]+)))',
    excludeRegex:
      '(?:writeFileSync|appendFileSync|\\.write\\s*\\(|write_text\\s*\\(|open\\s*\\([^)]*[\'"][wa][\'"]|\\bsed\\s+-i|\\bperl\\s+-[pi])',
    targetFailureMode: 'INLINE_VERIFICATION_UNRECOGNIZED',
    rationale:
      'Credit non-mutating exit-0 shell test suites and inline assertion scripts (node -e, python3 -c, node verify.mjs) as verification_passed when omitted by the caller.'
  }),
  Object.freeze({
    id: 'GH-EVO-04',
    action: SYNTHESIZED_RULE_ACTIONS.HOLD_PSEUDO_COMPLETION_LOOP,
    toolPattern: '^(?:bash|sh|shell|run_command|run_shell|exec)$',
    commandRegex:
      '^\\s*(?:echo|printf)\\b(?![^\\n]*COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT)(?![^\\n]*[>|])[^\\n]*\\b(?:task\\s+complete\\w*|completed\\s+successfully|final\\s+(?:task\\s+)?verification|implementation\\s+complete|fix\\s+confirmed|ready\\s+for\\s+use|successfully\\s+(?:fixed|implemented|enhanced))\\b',
    minConsecutiveMatches: 2,
    targetFailureMode: 'PSEUDO_COMPLETION_ECHO_LOOP',
    correctivePrompt:
      'Repeated completion-summary echo detected without submitting. Do not run celebratory echo banners; invoke your submit marker/tool (or return your final answer directly) now.',
    rationale:
      'Interrupt closeout echo-spin loops before burning remaining step budget into LimitsExceeded.'
  }),
  Object.freeze({
    id: 'GH-EVO-05',
    action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF,
    toolPattern: '^(?:bash|sh|shell|run_command|run_shell|exec)$',
    commandRegex:
      '^\\s*(?:cd\\s+\\S+\\s*&&\\s*)?git\\s+(?:diff|show|format-patch)\\b[^;|\\n]*>\\s*(?:/tmp/|\\./)?(?:patch\\.txt|[\\w.-]+\\.(?:patch|diff))\\s*$',
    targetFailureMode: 'PATCH_EXPORT_FALSE_DIFF',
    rationale:
      'Prevent pre-submit read-only patch exports (git diff > patch.txt / *.patch) from dirtying pending_diffs_count after tests have already passed.'
  })
]);

/**
 * Safely validate and compile a candidate regular expression, rejecting overly broad catch-alls,
 * excessive length, nested-quantifier ReDoS risks, and invalid syntax.
 *
 * @param {string} pattern
 * @param {string} [flags='i']
 */
export function compileSafeRuleRegex(pattern, flags = 'i') {
  const raw = String(pattern ?? '').trim();
  if (raw.length < 4) {
    return { ok: false, regex: null, error: 'Regex pattern too short (< 4 chars).' };
  }
  if (raw.length > 420) {
    return { ok: false, regex: null, error: 'Regex pattern exceeds 420-char safety bound.' };
  }
  if (TRIVIAL_REGEX_PATTERNS.has(raw)) {
    return { ok: false, regex: null, error: `Trivial catch-all pattern "${raw}" is forbidden.` };
  }
  if (NESTED_QUANTIFIER_RE.test(raw)) {
    return { ok: false, regex: null, error: 'Nested quantifier pattern rejected (ReDoS guard).' };
  }
  const safeFlags = String(flags ?? 'i').replace(/[^gimsuy]/g, '').replace(/g/g, '');
  try {
    const regex = new RegExp(raw, safeFlags);
    return { ok: true, regex, error: null };
  } catch (err) {
    return { ok: false, regex: null, error: `Invalid RegExp syntax: ${err.message}` };
  }
}

/**
 * Compile an array of rule definitions into executable rule descriptors, skipping invalid entries.
 *
 * @param {Array<object>} [rules=[]]
 */
export function compileExecutableRules(rules = []) {
  if (!Array.isArray(rules)) return [];
  const compiled = [];

  for (const rawRule of rules) {
    if (!rawRule || typeof rawRule !== 'object') continue;
    const action = String(rawRule.action ?? '').trim();
    if (!VALID_RULE_ACTIONS.has(action)) continue;

    const toolCheck = compileSafeRuleRegex(
      rawRule.toolPattern || '^(?:bash|sh|shell|run_command|run_shell|exec)$',
      'i'
    );
    const cmdCheck = compileSafeRuleRegex(rawRule.commandRegex || '', 'i');
    if (!toolCheck.ok || !cmdCheck.ok) continue;

    let excludeRe = null;
    if (rawRule.excludeRegex) {
      const exCheck = compileSafeRuleRegex(rawRule.excludeRegex, 'i');
      if (!exCheck.ok) continue;
      excludeRe = exCheck.regex;
    }

    compiled.push({
      id: String(rawRule.id || `GH-SYN-${compiled.length + 1}`),
      action,
      toolRe: toolCheck.regex,
      commandRe: cmdCheck.regex,
      excludeRe,
      minConsecutiveMatches: Math.max(1, Math.trunc(Number(rawRule.minConsecutiveMatches ?? 1) || 1)),
      correctivePrompt: String(
        rawRule.correctivePrompt ||
          'Intercepted by Meta-Harness rule: adjust your command or invoke the submit action.'
      ),
      targetFailureMode: String(rawRule.targetFailureMode || 'GENERAL'),
      rationale: String(rawRule.rationale || '')
    });
  }

  return compiled;
}

function extractBashFenceCommand(text = '') {
  const match = String(text).match(/```(?:bash|sh|shell)\s*\n([\s\S]*?)```/i);
  return match ? match[1].trim() : '';
}

function parseObservationReturnCode(text = '') {
  const rcMatch = String(text).match(/<returncode>\s*(-?\d+)\s*<\/returncode>/i);
  return rcMatch ? Number.parseInt(rcMatch[1], 10) : null;
}

function parseObservationOutput(text = '') {
  const outMatch = String(text).match(/<output>([\s\S]*?)<\/output>/i);
  return (outMatch ? outMatch[1] : String(text)).trim();
}

/**
 * Extract ordered shell action/observation steps from a `.traj.json` payload or `grounded_events` list.
 *
 * @param {object} trajData
 */
export function extractShellCommandsFromTrajectory(trajData) {
  if (!trajData || typeof trajData !== 'object') return [];

  if (Array.isArray(trajData.events)) {
    return trajData.events
      .map((ev, idx) => {
        let cmd = '';
        try {
          const parsed = JSON.parse(ev.canonical_args_json || '{}');
          cmd = String(parsed.command ?? parsed.cmd ?? '');
        } catch {
          cmd = '';
        }
        return {
          step: Number(ev.step ?? idx + 1),
          command: cmd,
          returncode: ev.status === 'COMMITTED' ? 0 : ev.status === 'FAILED' ? 1 : null,
          outputPreview: String(ev.result_preview ?? '').slice(0, 400),
          assistantText: ''
        };
      })
      .filter((item) => item.command.length > 0);
  }

  const messages = Array.isArray(trajData.messages) ? trajData.messages : [];
  const steps = [];
  let stepCounter = 0;

  for (let i = 0; i < messages.length; i += 1) {
    const msg = messages[i];
    if (!msg || msg.role !== 'assistant') continue;

    const actions = Array.isArray(msg?.extra?.actions) ? msg.extra.actions : [];
    const commands = actions.map((a) => String(a?.command ?? '').trim()).filter(Boolean);

    if (commands.length === 0) {
      const fenced = extractBashFenceCommand(msg.content || '');
      if (fenced) commands.push(fenced);
    }
    if (commands.length === 0) continue;

    const nextMsg = messages[i + 1];
    const obsContent =
      nextMsg && (nextMsg.role === 'tool' || nextMsg.role === 'user')
        ? String(nextMsg.content ?? '')
        : '';
    const returncode = parseObservationReturnCode(obsContent);
    const outputPreview = parseObservationOutput(obsContent).slice(0, 400);

    for (const command of commands) {
      stepCounter += 1;
      steps.push({
        step: stepCounter,
        command,
        returncode,
        outputPreview,
        assistantText: String(msg.content ?? '').slice(0, 300)
      });
    }
  }

  return steps;
}

function locateTrajectoryFile(row, trajDirs = []) {
  const taskId = String(row?.task_id ?? '').trim();
  const cfg = String(row?.config ?? '').trim();
  if (!taskId) return null;

  for (const baseDir of trajDirs) {
    if (!baseDir) continue;
    const candidates = [
      cfg ? path.join(baseDir, cfg, `${taskId}.traj.json`) : null,
      cfg ? path.join(baseDir, 'traj', cfg, `${taskId}.traj.json`) : null,
      path.join(baseDir, `${taskId}.traj.json`)
    ].filter(Boolean);

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

const CELEBRATORY_ECHO_DETECT_RE =
  /^\s*(?:echo|printf)\b(?![^\n]*COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT)(?![^\n]*[>|])[^\n]*\b(?:task\s+complete\w*|completed\s+successfully|final\s+(?:task\s+)?verification|implementation\s+complete|fix\s+confirmed|ready\s+for\s+use|successfully\s+(?:fixed|implemented|enhanced))\b/i;

const SHELL_CORRUPTION_OUTPUT_RE =
  /SyntaxError:\s+(?:Unexpected token|Identifier\s+'[^']+'\s+has already been declared)|Backslash found where operator expected|syntax error near unexpected token/i;

const GIT_RESTORE_CMD_RE =
  /^\s*(?:cd\s+\S+\s*&&\s*)?git\s+(?:checkout\s+(?:HEAD\s+)?--\s+\S+|restore\s+\S+)/i;

const TEMP_RM_CMD_RE =
  /^\s*(?:cd\s+\S+\s*&&\s*)?rm\s+(?:-[rfv]+\s+)*(?![^\n]*\btests?\/)(?:(?:\.\/|\/tmp\/)?(?:test[_-][\w.-]+|[\w.-]+[_-]test\.[A-Za-z0-9]+|verify[_-]?[\w.-]*|simple_test\.[\w.-]+|[\w.-]+\.(?:bak|orig|tmp)))/i;

function classifyEpisodeFailureModes(row, steps = []) {
  const modes = new Set();
  const resolved = row.resolved === true;
  const submitted =
    row.submitted === true || row.exit_status === 'Submitted' || row.exit_status === 'COMMITTED';
  const blockedReason = String(row.blocked_reason || '');
  const exitStatus = String(row.exit_status || '');
  const patchLines = Number(row.patch_lines || 0);

  if (resolved && submitted && !blockedReason && patchLines < 400) {
    return { isCleanPass: true, modes: ['CLEAN_PASS'] };
  }

  let celebratoryEchoCount = 0;
  let shellCorruptionHits = 0;
  let gitRestoreAttempts = 0;
  let tempCleanupHits = 0;

  for (const st of steps) {
    if (CELEBRATORY_ECHO_DETECT_RE.test(st.command)) {
      celebratoryEchoCount += 1;
    }
    if (SHELL_CORRUPTION_OUTPUT_RE.test(st.outputPreview)) {
      shellCorruptionHits += 1;
    }
    if (GIT_RESTORE_CMD_RE.test(st.command)) {
      gitRestoreAttempts += 1;
    }
    if (TEMP_RM_CMD_RE.test(st.command)) {
      tempCleanupHits += 1;
    }
  }

  if (
    celebratoryEchoCount >= 2 ||
    (exitStatus === 'LimitsExceeded' && celebratoryEchoCount >= 1)
  ) {
    modes.add('PSEUDO_COMPLETION_ECHO_LOOP');
  }
  if (patchLines >= 400) {
    modes.add('UNTRACKED_SCRATCH_POLLUTION');
  }
  if (
    blockedReason.includes('BLOCK_DUPLICATE_WRITE') &&
    (gitRestoreAttempts > 0 || steps.length === 0)
  ) {
    modes.add('IDEMPOTENT_ROLLBACK_BLOCKED');
  }
  if (
    blockedReason.includes('STOP_BLOCKED:FORCE_VERIFY') ||
    blockedReason.includes('ABORT_UNVERIFIED')
  ) {
    modes.add('INLINE_VERIFICATION_UNRECOGNIZED');
    if (tempCleanupHits > 0) {
      modes.add('TEMP_CLEANUP_FALSE_DIFF');
    }
  }
  if (shellCorruptionHits > 0) {
    modes.add('SHELL_EDIT_CORRUPTION_SPIRAL');
  }
  if (
    exitStatus === 'RepeatedFormatError' ||
    exitStatus === 'BadRequestError' ||
    exitStatus === 'Error'
  ) {
    modes.add('FORMAT_OR_TRUNCATION_STALL');
  }
  if (modes.size === 0 && (!resolved || !submitted)) {
    modes.add('PREMATURE_STOP_OR_LIMITS');
  }

  return {
    isCleanPass: false,
    modes: Array.from(modes)
  };
}

/**
 * Stage A: Deterministically mine failure modes and command corpora from graded JSONL results
 * and optional `.traj.json` trajectory directories (0 LLM calls).
 *
 * @param {object} [options={}]
 */
export function mineFailureTrajectories({
  resultsPaths = [],
  rows = [],
  trajDirs = []
} = {}) {
  const allRows = Array.isArray(rows) ? [...rows] : [];

  for (const filePath of resultsPaths) {
    if (!filePath || !fs.existsSync(filePath)) continue;
    const rawLines = fs.readFileSync(filePath, 'utf8').split('\n');
    for (const line of rawLines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        allRows.push(JSON.parse(trimmed));
      } catch {
        // Ignore malformed JSONL lines
      }
    }
  }

  if (allRows.length === 0) {
    return okEnvelope(
      'krusch_mine_failure_traces',
      'No benchmark result rows provided or found at resultsPaths.',
      { code: 'VALIDATION_ERROR', resultsPaths },
      false
    );
  }

  const failureTaxonomy = {};
  const minedSamples = [];
  const passingCommandSet = new Set(CANONICAL_CLEAN_COMMANDS);
  const failingCommandSet = new Set();
  let cleanPassEpisodes = 0;
  let failedOrSuboptimalEpisodes = 0;
  let hydratedTrajFiles = 0;

  for (const row of allRows) {
    const trajPath = locateTrajectoryFile(row, trajDirs);
    let steps = [];
    if (trajPath) {
      try {
        const trajJson = JSON.parse(fs.readFileSync(trajPath, 'utf8'));
        steps = extractShellCommandsFromTrajectory(trajJson);
        hydratedTrajFiles += 1;
      } catch {
        steps = [];
      }
    } else if (Array.isArray(row.steps)) {
      steps = row.steps;
    }

    const classification = classifyEpisodeFailureModes(row, steps);
    if (classification.isCleanPass) {
      cleanPassEpisodes += 1;
      for (const st of steps) {
        if (st.command && st.returncode === 0) {
          passingCommandSet.add(st.command);
        }
      }
      continue;
    }

    failedOrSuboptimalEpisodes += 1;
    for (const st of steps) {
      if (st.command) {
        failingCommandSet.add(st.command);
      }
    }

    for (const mode of classification.modes) {
      if (!failureTaxonomy[mode]) {
        failureTaxonomy[mode] = {
          count: 0,
          totalTurns: 0,
          maxPatchLines: 0,
          exampleTasks: []
        };
      }
      const bucket = failureTaxonomy[mode];
      bucket.count += 1;
      bucket.totalTurns += Number(row.turns || 0);
      bucket.maxPatchLines = Math.max(bucket.maxPatchLines, Number(row.patch_lines || 0));
      if (bucket.exampleTasks.length < 5) {
        bucket.exampleTasks.push(`${row.config || '?'}:${row.task_id}`);
      }
    }

    if (minedSamples.length < 16) {
      minedSamples.push({
        task_id: row.task_id,
        config: row.config,
        resolved: Boolean(row.resolved),
        exit_status: row.exit_status,
        turns: Number(row.turns || 0),
        patch_lines: Number(row.patch_lines || 0),
        blocked_reason: row.blocked_reason || null,
        modes: classification.modes,
        tail_commands: steps.slice(-5).map((s) => ({
          command: s.command.slice(0, 180),
          returncode: s.returncode,
          outputPreview: s.outputPreview.slice(0, 160)
        }))
      });
    }
  }

  return okEnvelope(
    'krusch_mine_failure_traces',
    `Mined ${allRows.length} episode(s) (${hydratedTrajFiles} step trace(s)): ${cleanPassEpisodes} clean pass, ${failedOrSuboptimalEpisodes} failed/suboptimal across ${Object.keys(failureTaxonomy).length} failure mode(s)`,
    {
      totalEpisodes: allRows.length,
      hydratedTrajFiles,
      cleanPassEpisodes,
      failedEpisodes: failedOrSuboptimalEpisodes,
      failureTaxonomy,
      minedSamples,
      passingCommandCorpus: Array.from(passingCommandSet),
      failingCommandCorpus: Array.from(failingCommandSet)
    }
  );
}

/**
 * Stage C: Deterministic Holdout Replay Gate.
 * Rejects any candidate rule with invalid/ReDoS regex syntax, policy-floor subversion,
 * or `falsePositiveHits > 0` on clean passing trajectories and canonical safe commands.
 *
 * @param {Array<object>} [candidateRules=[]]
 * @param {object} [context={}]
 */
export function verifyCandidateRulesOnTraces(
  candidateRules = [],
  { passingCommands = [], failingCommands = [], failureTaxonomy = {} } = {}
) {
  const cleanSet = Array.from(new Set([...CANONICAL_CLEAN_COMMANDS, ...passingCommands]));
  const failSet = Array.isArray(failingCommands) ? failingCommands : [];

  const acceptedRules = [];
  const rejectedRules = [];
  const seenSignatures = new Set();

  for (let idx = 0; idx < candidateRules.length; idx += 1) {
    const raw = candidateRules[idx];
    if (!raw || typeof raw !== 'object') continue;

    const id = String(raw.id || `GH-CAND-${idx + 1}`).trim();
    const action = String(raw.action || '').trim();

    if (!VALID_RULE_ACTIONS.has(action)) {
      rejectedRules.push({
        id,
        action,
        status: 'REJECTED_INVALID_ACTION',
        reason: `Unsupported rule action "${action}".`,
        falsePositiveHits: 0,
        truePositiveHits: 0
      });
      continue;
    }

    const toolPattern = String(
      raw.toolPattern || '^(?:bash|sh|shell|run_command|run_shell|exec)$'
    ).trim();
    const commandRegex = String(raw.commandRegex || '').trim();
    const dedupKey = `${action}::${toolPattern}::${commandRegex}`;
    if (seenSignatures.has(dedupKey)) {
      continue;
    }
    seenSignatures.add(dedupKey);

    const toolComp = compileSafeRuleRegex(toolPattern, 'i');
    const cmdComp = compileSafeRuleRegex(commandRegex, 'i');
    if (!toolComp.ok || !cmdComp.ok) {
      rejectedRules.push({
        id,
        action,
        commandRegex,
        status: 'REJECTED_INVALID_REGEX',
        reason: toolComp.error || cmdComp.error,
        falsePositiveHits: 0,
        truePositiveHits: 0
      });
      continue;
    }

    let excludeComp = { ok: true, regex: null };
    if (raw.excludeRegex) {
      excludeComp = compileSafeRuleRegex(String(raw.excludeRegex), 'i');
      if (!excludeComp.ok) {
        rejectedRules.push({
          id,
          action,
          commandRegex,
          status: 'REJECTED_INVALID_REGEX',
          reason: `excludeRegex error: ${excludeComp.error}`,
          falsePositiveHits: 0,
          truePositiveHits: 0
        });
        continue;
      }
    }

    const matchesCommand = (cmd) => {
      if (!cmdComp.regex.test(cmd)) return false;
      if (excludeComp.regex && excludeComp.regex.test(cmd)) return false;
      return true;
    };

    const isRelaxationRule =
      action === SYNTHESIZED_RULE_ACTIONS.EXEMPT_DUPLICATE_WRITE ||
      action === SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF ||
      action === SYNTHESIZED_RULE_ACTIONS.CREDIT_INLINE_VERIFY;

    let subvertsPolicyFloor = false;
    if (isRelaxationRule) {
      for (const probeCmd of FORBIDDEN_EXEMPT_PROBES) {
        if (DESTRUCTIVE_FLOOR_RE.test(probeCmd) && matchesCommand(probeCmd)) {
          subvertsPolicyFloor = true;
          break;
        }
      }
    }
    if (subvertsPolicyFloor) {
      rejectedRules.push({
        id,
        action,
        commandRegex,
        status: 'REJECTED_POLICY_FLOOR_CONFLICT',
        reason: 'Rule matched a destructive command protected by the frozen policy floor.',
        falsePositiveHits: 1,
        truePositiveHits: 0
      });
      continue;
    }

    const isBlockingOrHolding =
      action === SYNTHESIZED_RULE_ACTIONS.HOLD_TOOL_PATTERN ||
      action === SYNTHESIZED_RULE_ACTIONS.HOLD_PSEUDO_COMPLETION_LOOP;

    const falsePositiveExamples = [];
    if (isBlockingOrHolding) {
      for (const cleanCmd of cleanSet) {
        if (matchesCommand(cleanCmd)) {
          falsePositiveExamples.push(cleanCmd.slice(0, 140));
          if (falsePositiveExamples.length >= 3) break;
        }
      }
    } else if (action === SYNTHESIZED_RULE_ACTIONS.EXEMPT_DUPLICATE_WRITE) {
      for (const mutationProbe of [
        'sed -i "s/foo/bar/" src/index.js',
        'echo "x" > src/index.js',
        'python3 -c "open(\'a.py\', \'w\').write(\'1\')"'
      ]) {
        if (matchesCommand(mutationProbe)) {
          falsePositiveExamples.push(mutationProbe);
        }
      }
    } else if (action === SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF) {
      for (const trackedDeleteProbe of [
        'rm src/index.js',
        'rm -f lib/config.js',
        'rm -rf src/',
        'rm tests/core.test.js',
        'cd /testbed && rm tests/unit_test.js'
      ]) {
        if (matchesCommand(trackedDeleteProbe)) {
          falsePositiveExamples.push(trackedDeleteProbe);
        }
      }
    }

    if (falsePositiveExamples.length > 0) {
      rejectedRules.push({
        id,
        action,
        commandRegex,
        status: 'REJECTED_FALSE_POSITIVE',
        reason: `Triggered ${falsePositiveExamples.length} false positive(s) on clean/protected command corpus.`,
        falsePositiveHits: falsePositiveExamples.length,
        falsePositiveExamples,
        truePositiveHits: 0
      });
      continue;
    }

    let truePositiveHits = 0;
    for (const failCmd of failSet) {
      if (matchesCommand(failCmd)) {
        truePositiveHits += 1;
      }
    }
    const targetMode = String(raw.targetFailureMode || '');
    const taxonomyEpisodes = Number(failureTaxonomy[targetMode]?.count || 0);

    acceptedRules.push({
      id,
      action,
      toolPattern,
      commandRegex,
      ...(raw.excludeRegex ? { excludeRegex: String(raw.excludeRegex) } : {}),
      minConsecutiveMatches: Math.max(1, Math.trunc(Number(raw.minConsecutiveMatches ?? 1) || 1)),
      ...(raw.correctivePrompt ? { correctivePrompt: String(raw.correctivePrompt) } : {}),
      targetFailureMode: targetMode || 'GENERAL',
      rationale: String(raw.rationale || ''),
      status: 'ACCEPTED',
      falsePositiveHits: 0,
      truePositiveHits,
      targetedFailureEpisodes: taxonomyEpisodes
    });
  }

  return {
    acceptedRules,
    rejectedRules,
    verificationSummary: {
      evaluatedCount: acceptedRules.length + rejectedRules.length,
      acceptedCount: acceptedRules.length,
      rejectedCount: rejectedRules.length,
      cleanCorpusSize: cleanSet.length,
      failingCorpusSize: failSet.length
    }
  };
}

function normalizeTeacherApiUrl(rawHost = '') {
  const base = String(
    rawHost || process.env.OLLAMA_URL || process.env.OLLAMA_HOST || 'http://127.0.0.1:11434'
  )
    .trim()
    .replace(/\/+$/, '');
  if (base.endsWith('/v1/chat/completions')) return base;
  if (base.endsWith('/v1')) return `${base}/chat/completions`;
  return `${base}/v1/chat/completions`;
}

function extractFirstJsonObject(rawText = '') {
  const text = String(rawText || '').trim();
  const stripped = text.replace(/^```(?:json)?\s*\r?\n([\s\S]*?)\r?\n```$/i, '$1').trim();
  try {
    return JSON.parse(stripped);
  } catch {
    const start = stripped.indexOf('{');
    const end = stripped.lastIndexOf('}');
    if (start >= 0 && end > start) {
      return JSON.parse(stripped.slice(start, end + 1));
    }
    throw new Error('Teacher response did not contain valid JSON.');
  }
}

/**
 * Stage B: Query an optional Teacher LLM via injectable `chatJsonFn` or OpenAI-compatible
 * `/v1/chat/completions` endpoint to propose candidate harness rules.
 *
 * @param {object} miningData
 * @param {object} [options={}]
 */
export async function synthesizeRulesWithTeacher(miningData, options = {}) {
  const model = String(options.model || process.env.OLLAMA_MODEL || 'qwen3-coder-30b-moe:latest');
  const apiUrl = normalizeTeacherApiUrl(options.apiUrl);
  const timeoutMs = Math.max(1000, Number(options.timeoutMs || 60000));

  const systemPrompt = [
    'You are a Principal Agentic Harness Engineer implementing Meta-Harness Evolving (EmoHarness / Infrathon).',
    'Given empirical failure modes and tail shell commands from failed coding-agent episodes, propose 1 to 4 deterministic regex rules.',
    'Each rule MUST use one of these exact actions:',
    '- "HOLD_PSEUDO_COMPLETION_LOOP": hold non-submitting celebratory echo loops.',
    '- "EXEMPT_DUPLICATE_WRITE": exempt safe idempotent single-file git restore/checkout commands from duplicate-write blocks.',
    '- "EXEMPT_CLEANUP_DIFF": exempt rm cleanup of temporary test/scratch files from dirtying pending_diffs_count.',
    '- "CREDIT_INLINE_VERIFY": credit non-mutating exit-0 test/assertion commands as verification_passed.',
    '- "HOLD_TOOL_PATTERN": soft-hold a specific broken shell anti-pattern that NEVER appears in clean passing trajectories.',
    'CRITICAL: Any HOLD rule that matches clean passing commands (such as `pytest`, `node --test`, `git diff`, `sed -n`, or `echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT`) will be automatically REJECTED by the holdout verifier.',
    'Respond ONLY with valid JSON matching: { "rules": [ { "id": "GH-LLM-01", "action": "...", "toolPattern": "^(?:bash|sh|shell|run_command|run_shell|exec)$", "commandRegex": "...", "excludeRegex": "", "minConsecutiveMatches": 1, "targetFailureMode": "...", "correctivePrompt": "...", "rationale": "..." } ] }'
  ].join('\n');

  const userPayload = JSON.stringify(
    {
      failureTaxonomy: miningData.failureTaxonomy,
      sampleFailures: (miningData.minedSamples || []).slice(0, 8),
      cleanCommandsNeverBlock: CANONICAL_CLEAN_COMMANDS
    },
    null,
    2
  );

  try {
    if (typeof options.chatJsonFn === 'function') {
      const parsed = await options.chatJsonFn({ systemPrompt, userPayload, model, apiUrl });
      const rules = Array.isArray(parsed?.rules) ? parsed.rules : [];
      return { ok: true, model, rules, error: null };
    }

    const headers = { 'Content-Type': 'application/json' };
    const apiKey = options.apiKey || process.env.OPENAI_API_KEY || '';
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }

    const res = await fetch(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model,
        temperature: 0.1,
        max_tokens: 2200,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPayload }
        ]
      }),
      signal: AbortSignal.timeout(timeoutMs)
    });

    if (!res.ok) {
      return {
        ok: false,
        model,
        rules: [],
        error: `Teacher HTTP ${res.status}`
      };
    }

    const body = await res.json();
    const content = String(body?.choices?.[0]?.message?.content || '');
    const parsed = extractFirstJsonObject(content);
    const rules = Array.isArray(parsed?.rules) ? parsed.rules : [];
    return { ok: true, model, rules, error: null };
  } catch (err) {
    return {
      ok: false,
      model,
      rules: [],
      error: err?.message || String(err)
    };
  }
}

/**
 * Full 3-Stage Meta-Harness Rule Evolution pipeline (`mine -> synthesize -> holdout-verify`).
 *
 * @param {object} [options={}]
 */
export async function evolveRulesFromTraces(options = {}) {
  const mined = mineFailureTrajectories({
    resultsPaths: options.resultsPaths || [],
    rows: options.rows || [],
    trajDirs: options.trajDirs || []
  });
  if (!mined.ok) {
    return mined;
  }

  const candidatePool = [];
  if (options.includeDefaultRules !== false) {
    candidatePool.push(...DEFAULT_EVOLVED_HARNESS_RULES);
  }
  if (Array.isArray(options.extraCandidateRules)) {
    candidatePool.push(...options.extraCandidateRules);
  }

  let teacherResult = { ok: false, model: null, rules: [], error: null };
  if (options.useTeacher === true) {
    teacherResult = await synthesizeRulesWithTeacher(mined.data, {
      model: options.model,
      apiUrl: options.apiUrl,
      apiKey: options.apiKey,
      timeoutMs: options.timeoutMs,
      chatJsonFn: options.chatJsonFn
    });
    if (teacherResult.rules.length > 0) {
      candidatePool.push(...teacherResult.rules);
    }
  }

  const verified = verifyCandidateRulesOnTraces(candidatePool, {
    passingCommands: mined.data.passingCommandCorpus,
    failingCommands: mined.data.failingCommandCorpus,
    failureTaxonomy: mined.data.failureTaxonomy
  });

  if (options.outputPath) {
    const resolvedOut = path.resolve(options.outputPath);
    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    fs.writeFileSync(
      resolvedOut,
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          sourceEpisodes: mined.data.totalEpisodes,
          teacherModel: teacherResult.ok ? teacherResult.model : null,
          acceptedRules: verified.acceptedRules,
          rejectedRules: verified.rejectedRules
        },
        null,
        2
      ),
      'utf8'
    );
  }

  return okEnvelope(
    'krusch_evolve_harness_rules',
    `Evolved ${verified.acceptedRules.length} verified harness rule(s) (${verified.rejectedRules.length} rejected by holdout gate) from ${mined.data.totalEpisodes} trace(s)`,
    {
      mining: {
        totalEpisodes: mined.data.totalEpisodes,
        hydratedTrajFiles: mined.data.hydratedTrajFiles,
        cleanPassEpisodes: mined.data.cleanPassEpisodes,
        failedEpisodes: mined.data.failedEpisodes,
        failureTaxonomy: mined.data.failureTaxonomy,
        minedSamples: mined.data.minedSamples
      },
      teacher: {
        invoked: options.useTeacher === true,
        ok: teacherResult.ok,
        model: teacherResult.model,
        proposedCount: teacherResult.rules.length,
        error: teacherResult.error
      },
      acceptedRules: verified.acceptedRules,
      rejectedRules: verified.rejectedRules,
      verificationSummary: verified.verificationSummary,
      outputPath: options.outputPath ? path.resolve(options.outputPath) : null
    }
  );
}

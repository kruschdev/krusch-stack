/**
 * @module engines/context-engine
 * Tier 1: Working Memory, Architectural Invariants & Lineage (krusch-context-mcp).
 * Implements retrieve, remember, revise, nudge, and health with INV-12 span-grounded drift detection.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

const VALID_CATEGORIES = new Set(['decision', 'invariant', 'bug', 'lesson', 'blocker']);
const VALID_REVISE_ACTIONS = new Set(['supersede', 'invalidate']);

/**
 * Compute SHA-256 hex digest of a string.
 * @param {string} input
 * @returns {string}
 */
function sha256(input) {
  return crypto.createHash('sha256').update(String(input ?? ''), 'utf8').digest('hex');
}

/**
 * Parse a line-range locator such as "L10-L20", "10-20", or "L15".
 * @param {string} [locator]
 * @returns {{ startLine: number, endLine: number } | null}
 */
function parseLineLocator(locator) {
  if (!locator || typeof locator !== 'string') return null;
  const match = locator.trim().match(/^L?(\d+)(?:\s*-\s*L?(\d+))?$/i);
  if (!match) return null;
  const startLine = Number.parseInt(match[1], 10);
  const endLine = match[2] ? Number.parseInt(match[2], 10) : startLine;
  if (Number.isNaN(startLine) || startLine < 1 || endLine < startLine) return null;
  return { startLine, endLine };
}

/**
 * Extract slice of file lines (1-indexed inclusive).
 * @param {string} fileContent
 * @param {{ startLine: number, endLine: number } | null} range
 * @returns {string}
 */
function extractLocatorSpan(fileContent, range) {
  const lines = String(fileContent).split(/\r?\n/);
  if (!range) return lines.join('\n');
  const slice = lines.slice(range.startLine - 1, range.endLine);
  return slice.join('\n');
}

/**
 * Compute initial anchor hash for a memory's provenance.
 * @param {object} provenance
 * @param {string} workspaceRoot
 * @returns {string | null}
 */
function computeProvenanceAnchorHash(provenance, workspaceRoot) {
  if (!provenance || typeof provenance !== 'object') return null;
  if (provenance.anchor_hash && typeof provenance.anchor_hash === 'string') {
    return provenance.anchor_hash;
  }

  const quoted = typeof provenance.quoted_sentence === 'string'
    ? provenance.quoted_sentence.trim()
    : '';
  const relFile = typeof provenance.file === 'string' ? provenance.file.trim() : '';
  const locator = typeof provenance.locator === 'string' ? provenance.locator.trim() : '';

  if (relFile) {
    const absPath = path.isAbsolute(relFile)
      ? path.resolve(relFile)
      : path.resolve(workspaceRoot, relFile);
    if (fs.existsSync(absPath) && fs.statSync(absPath).isFile()) {
      const fileContent = fs.readFileSync(absPath, 'utf8');
      if (quoted) {
        return sha256(quoted);
      }
      const range = parseLineLocator(locator);
      const spanText = extractLocatorSpan(fileContent, range).trim();
      return sha256(spanText);
    }
    return sha256(quoted || `${relFile}:${locator}`);
  }

  if (quoted) {
    return sha256(quoted);
  }

  return null;
}

/**
 * Evaluate INV-12 span-grounded drift for a context memory record.
 * Returns 'VALID', 'HEALED_LINE_SHIFT', or 'STALE_DRIFT'.
 * @param {object} row
 * @param {string} workspaceRoot
 * @returns {{ status: 'VALID' | 'HEALED_LINE_SHIFT' | 'STALE_DRIFT', current_locator?: string }}
 */
function evaluateSpanDrift(row, workspaceRoot) {
  const relFile = row.provenance_file;
  const locator = row.provenance_locator;
  const quoted = row.quoted_sentence ? row.quoted_sentence.trim() : '';
  const anchorHash = row.anchor_hash;

  if (!relFile && !quoted && !anchorHash) {
    return { status: 'VALID' };
  }

  if (relFile) {
    const absPath = path.isAbsolute(relFile)
      ? path.resolve(relFile)
      : path.resolve(workspaceRoot, relFile);
    if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
      return { status: 'STALE_DRIFT' };
    }

    const fileContent = fs.readFileSync(absPath, 'utf8');
    const range = parseLineLocator(locator);

    if (quoted) {
      if (range) {
        const spanText = extractLocatorSpan(fileContent, range);
        if (spanText.includes(quoted)) {
          return { status: 'VALID' };
        }
      }
      if (fileContent.includes(quoted)) {
        if (range) {
          const lines = fileContent.split(/\r?\n/);
          const foundIdx = lines.findIndex((line) => line.includes(quoted));
          const healedLocator = foundIdx >= 0 ? `L${foundIdx + 1}` : locator;
          return { status: 'HEALED_LINE_SHIFT', current_locator: healedLocator };
        }
        return { status: 'VALID' };
      }
      return { status: 'STALE_DRIFT' };
    }

    if (anchorHash) {
      const spanText = extractLocatorSpan(fileContent, range).trim();
      const currentHash = sha256(spanText);
      if (currentHash === anchorHash) {
        return { status: 'VALID' };
      }
      return { status: 'STALE_DRIFT' };
    }

    return { status: 'VALID' };
  }

  if (quoted && anchorHash) {
    return sha256(quoted) === anchorHash
      ? { status: 'VALID' }
      : { status: 'STALE_DRIFT' };
  }

  return { status: 'VALID' };
}

/**
 * Extract forbidden tokens or patterns from an active invariant/decision statement.
 * @param {string} ruleText
 * @returns {string[]}
 */
function extractForbiddenPatterns(ruleText) {
  const patterns = new Set();
  const text = String(ruleText || '');
  const hasNegativeIntent = /\b(never|forbid|forbidden|prohibit|prohibited|must\s+not|do\s+not|don't|no|ban|banned|disallow|avoid)\b/i.test(text);

  if (hasNegativeIntent) {
    const backtickMatches = text.matchAll(/`([^`]{2,64})`/g);
    for (const match of backtickMatches) {
      const token = match[1].trim();
      if (token) patterns.add(token);
    }

    const verbMatches = text.matchAll(/\b(?:never\s+use|do\s+not\s+use|don't\s+use|forbid|prohibit|disallow|avoid|no)\s+([a-zA-Z0-9_.:/()-]{3,40})/gi);
    for (const match of verbMatches) {
      const token = match[1].trim().replace(/[.,;:]$/, '');
      const stopWords = new Set(['the', 'any', 'all', 'raw', 'direct', 'internal', 'private', 'local', 'code', 'file', 'files']);
      if (token && !stopWords.has(token.toLowerCase())) {
        patterns.add(token);
        const strippedParens = token.replace(/\(\)$/, '');
        if (strippedParens.length >= 3) {
          patterns.add(`${strippedParens}(`);
        }
      }
    }
  }

  return [...patterns];
}

/**
 * Create a Tier 1 Context Engine instance.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 */
export function createContextEngine({ db, workspaceRoot = process.cwd() }) {
  const root = path.resolve(workspaceRoot);

  const insertMemoryStmt = db.prepare(`
    INSERT INTO context_memories (
      category,
      content,
      status,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash
    ) VALUES (?, ?, 'active', ?, ?, ?, ?)
  `);

  const selectActiveStmt = db.prepare(`
    SELECT
      id,
      category,
      content,
      status,
      superseded_by,
      revocation_reason,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash,
      created_at,
      updated_at
    FROM context_memories
    WHERE status = 'active'
    ORDER BY id DESC
    LIMIT 250
  `);

  const selectByIdStmt = db.prepare(`
    SELECT * FROM context_memories WHERE id = ?
  `);

  const markSupersededStmt = db.prepare(`
    UPDATE context_memories
    SET status = 'superseded',
        superseded_by = ?,
        revocation_reason = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `);

  const markInvalidatedStmt = db.prepare(`
    UPDATE context_memories
    SET status = 'invalidated',
        revocation_reason = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `);

  /**
   * Persist a durable decision, invariant, bug, lesson, or blocker.
   * @param {object} [params]
   * @param {string} [params.category='decision']
   * @param {string} params.content
   * @param {object} [params.provenance={}]
   */
  function remember({ category = 'decision', content, provenance = {} } = {}) {
    const normalizedCategory = String(category || 'decision').trim().toLowerCase();
    if (!VALID_CATEGORIES.has(normalizedCategory)) {
      return okEnvelope(
        'krusch_context_remember',
        `Invalid category "${category}". Expected decision|invariant|bug|lesson|blocker.`,
        { error: `Invalid category: ${category}` },
        false
      );
    }

    const trimmedContent = String(content ?? '').trim();
    if (!trimmedContent) {
      return okEnvelope(
        'krusch_context_remember',
        'Memory content cannot be empty.',
        { error: 'content is required' },
        false
      );
    }

    const prov = provenance && typeof provenance === 'object' ? provenance : {};
    const provenanceFile = prov.file ? String(prov.file).trim() : null;
    const provenanceLocator = prov.locator ? String(prov.locator).trim() : null;
    const quotedSentence = prov.quoted_sentence ? String(prov.quoted_sentence).trim() : null;
    const anchorHash = computeProvenanceAnchorHash(
      {
        file: provenanceFile,
        locator: provenanceLocator,
        quoted_sentence: quotedSentence,
        anchor_hash: prov.anchor_hash
      },
      root
    );

    const result = insertMemoryStmt.run(
      normalizedCategory,
      trimmedContent,
      provenanceFile,
      provenanceLocator,
      quotedSentence,
      anchorHash
    );

    const id = Number(result.lastInsertRowid);
    const normalizedProvenance = {
      file: provenanceFile,
      locator: provenanceLocator,
      quoted_sentence: quotedSentence,
      anchor_hash: anchorHash
    };

    return okEnvelope(
      'krusch_context_remember',
      `Stored ${normalizedCategory} memory #${id}.`,
      {
        id,
        category: normalizedCategory,
        content: trimmedContent,
        status: 'active',
        provenance: normalizedProvenance
      },
      true
    );
  }

  /**
   * Retrieve active working memories, state briefing, and INV-12 drift telemetry.
   * @param {object} [params]
   * @param {string} [params.query='*']
   * @param {string} [params.category]
   * @param {boolean} [params.include_state=true]
   * @param {number} [params.limit_tokens=4000]
   */
  function retrieve({ query = '*', category, include_state = true, limit_tokens = 4000 } = {}) {
    const allActiveRows = selectActiveStmt.all();
    const totalActive = allActiveRows.length;

    const normalizedCat = category && category !== 'all' ? String(category).trim().toLowerCase() : null;
    const trimmedQuery = String(query ?? '*').trim();
    const isWildcard = !trimmedQuery || trimmedQuery === '*';
    const queryLower = trimmedQuery.toLowerCase();
    const queryTokens = isWildcard
      ? []
      : queryLower.split(/\s+/).filter((tok) => tok.length > 0);

    const driftSummary = {
      valid: 0,
      healed_line_shift: 0,
      stale_drift: 0
    };

    const items = [];
    let usedTokens = 0;
    const tokenBudget = Number.isFinite(Number(limit_tokens)) && Number(limit_tokens) > 0
      ? Number(limit_tokens)
      : 4000;

    for (const row of allActiveRows) {
      if (normalizedCat && row.category !== normalizedCat) {
        continue;
      }

      if (!isWildcard) {
        const haystack = [
          row.content,
          row.category,
          row.provenance_file || '',
          row.quoted_sentence || ''
        ].join(' ').toLowerCase();

        const matchesFull = haystack.includes(queryLower);
        const matchesTokens = queryTokens.length > 0 && queryTokens.every((t) => haystack.includes(t));
        const matchesAnyToken = queryTokens.length > 1 && queryTokens.some((t) => t.length >= 3 && haystack.includes(t));
        if (!matchesFull && !matchesTokens && !matchesAnyToken) {
          continue;
        }
      }

      const estimatedTokens = Math.max(1, Math.ceil(row.content.length / 4));
      if (items.length > 0 && usedTokens + estimatedTokens > tokenBudget) {
        break;
      }
      usedTokens += estimatedTokens;

      const drift = evaluateSpanDrift(row, root);
      if (drift.status === 'VALID') driftSummary.valid += 1;
      else if (drift.status === 'HEALED_LINE_SHIFT') driftSummary.healed_line_shift += 1;
      else driftSummary.stale_drift += 1;

      items.push({
        id: Number(row.id),
        category: row.category,
        content: row.content,
        status: row.status,
        drift_status: drift.status,
        provenance: {
          file: row.provenance_file || null,
          locator: drift.current_locator || row.provenance_locator || null,
          quoted_sentence: row.quoted_sentence || null,
          anchor_hash: row.anchor_hash || null
        },
        created_at: row.created_at,
        updated_at: row.updated_at
      });
    }

    const state = include_state
      ? {
          invariants: allActiveRows.filter((r) => r.category === 'invariant').length,
          decisions: allActiveRows.filter((r) => r.category === 'decision').length,
          blockers: allActiveRows.filter((r) => r.category === 'blocker').length,
          bugs: allActiveRows.filter((r) => r.category === 'bug').length,
          lessons: allActiveRows.filter((r) => r.category === 'lesson').length,
          token_budget: tokenBudget,
          tokens_used: usedTokens
        }
      : null;

    return okEnvelope(
      'krusch_context_retrieve',
      `Retrieved ${items.length} active memory item(s) (${driftSummary.stale_drift} drifted).`,
      {
        items,
        state,
        drift_summary: driftSummary,
        total_active: totalActive
      },
      true
    );
  }

  /**
   * Supersede or invalidate an existing context memory record with full lineage.
   * @param {object} [params]
   * @param {'supersede'|'invalidate'} [params.action='invalidate']
   * @param {number} params.target_id
   * @param {string} [params.new_content]
   * @param {string} [params.reason='Revised']
   */
  function revise({ action = 'invalidate', target_id, new_content, reason = 'Revised' } = {}) {
    const normalizedAction = String(action || 'invalidate').trim().toLowerCase();
    if (!VALID_REVISE_ACTIONS.has(normalizedAction)) {
      return okEnvelope(
        'krusch_context_revise',
        `Invalid revise action "${action}". Expected supersede or invalidate.`,
        { error: `Invalid action: ${action}` },
        false
      );
    }

    const numericId = Number(target_id);
    if (!Number.isInteger(numericId) || numericId <= 0) {
      return okEnvelope(
        'krusch_context_revise',
        'Valid target_id is required.',
        { error: 'target_id is required' },
        false
      );
    }

    const existing = selectByIdStmt.get(numericId);
    if (!existing) {
      return okEnvelope(
        'krusch_context_revise',
        `Memory #${numericId} not found.`,
        { target_id: numericId, error: 'not_found' },
        false
      );
    }

    const revocationReason = String(reason || 'Revised').trim();

    if (normalizedAction === 'supersede') {
      const replacementText = String(new_content ?? '').trim();
      if (!replacementText) {
        return okEnvelope(
          'krusch_context_revise',
          'new_content is required when action is "supersede".',
          { target_id: numericId, error: 'new_content_required' },
          false
        );
      }

      const insertResult = insertMemoryStmt.run(
        existing.category,
        replacementText,
        existing.provenance_file,
        existing.provenance_locator,
        existing.quoted_sentence,
        existing.anchor_hash
      );
      const newId = Number(insertResult.lastInsertRowid);
      markSupersededStmt.run(newId, revocationReason, numericId);

      return okEnvelope(
        'krusch_context_revise',
        `Superseded memory #${numericId} with memory #${newId}.`,
        {
          action: 'supersede',
          target_id: numericId,
          new_id: newId,
          superseded_by: newId,
          status: 'superseded',
          reason: revocationReason
        },
        true
      );
    }

    markInvalidatedStmt.run(revocationReason, numericId);
    return okEnvelope(
      'krusch_context_revise',
      `Invalidated memory #${numericId}.`,
      {
        action: 'invalidate',
        target_id: numericId,
        status: 'invalidated',
        reason: revocationReason
      },
      true
    );
  }

  /**
   * Audit staged code or diffs against active invariants and decisions (max 3 findings).
   * @param {object} [params]
   * @param {string} [params.trigger='pre_commit']
   * @param {string} [params.code='']
   */
  function nudge({ trigger = 'pre_commit', code = '' } = {}) {
    const codeText = String(code ?? '');
    const activeRows = selectActiveStmt.all().filter(
      (row) => row.category === 'invariant' || row.category === 'decision'
    );

    const findings = [];

    for (const row of activeRows) {
      if (findings.length >= 3) break;

      const forbiddenTokens = extractForbiddenPatterns(row.content);
      for (const token of forbiddenTokens) {
        if (codeText.includes(token)) {
          findings.push({
            memory_id: Number(row.id),
            category: row.category,
            severity: row.category === 'invariant' ? 'error' : 'warning',
            matched_token: token,
            rule: row.content,
            message: `Violation of ${row.category} #${row.id}: found forbidden pattern "${token}".`
          });
          break;
        }
      }
    }

    // Built-in sanitization check if code contains RFC1918 / CGNAT IP literals when invariant rules exist
    if (findings.length < 3 && codeText) {
      const privateIpRegex = new RegExp('\\b(?:192\\.168\\.\\d{1,3}\\.\\d{1,3}|10\\.10\\.10\\.\\d{1,3}|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.\\d{1,3}\\.\\d{1,3})\\b');
      const ipMatch = codeText.match(privateIpRegex);
      if (ipMatch) {
        findings.push({
          memory_id: null,
          category: 'invariant',
          severity: 'error',
          matched_token: ipMatch[0],
          rule: 'INV-STACK-04: Public Sanitization (no private LAN or mesh IP literals).',
          message: `Found private IP literal "${ipMatch[0]}" violating INV-STACK-04.`
        });
      }
    }

    const cappedFindings = findings.slice(0, 3);
    const passed = cappedFindings.length === 0;

    return okEnvelope(
      'krusch_context_nudge',
      passed
        ? `Audit (${trigger}) passed with 0 findings across ${activeRows.length} active rule(s).`
        : `Audit (${trigger}) flagged ${cappedFindings.length} finding(s).`,
      {
        trigger,
        passed,
        rules_checked: activeRows.length,
        findings: cappedFindings
      },
      true
    );
  }

  /**
   * Return store health counts and INV-12 drift statistics.
   */
  function health() {
    const countsRows = db.prepare(`
      SELECT status, COUNT(*) AS count
      FROM context_memories
      GROUP BY status
    `).all();

    const counts = {
      active: 0,
      superseded: 0,
      invalidated: 0
    };

    for (const row of countsRows) {
      if (row.status in counts) {
        counts[row.status] = Number(row.count);
      }
    }

    const activeRows = selectActiveStmt.all();
    let driftedCount = 0;
    let healedCount = 0;
    for (const row of activeRows) {
      const drift = evaluateSpanDrift(row, root);
      if (drift.status === 'STALE_DRIFT') driftedCount += 1;
      else if (drift.status === 'HEALED_LINE_SHIFT') healedCount += 1;
    }

    return okEnvelope(
      'krusch_context_health',
      `Context store healthy: ${counts.active} active, ${counts.superseded} superseded, ${counts.invalidated} invalidated, ${driftedCount} drifted.`,
      {
        active: counts.active,
        superseded: counts.superseded,
        invalidated: counts.invalidated,
        drifted_count: driftedCount,
        healed_count: healedCount,
        total: counts.active + counts.superseded + counts.invalidated
      },
      true
    );
  }

  return {
    retrieve,
    remember,
    revise,
    nudge,
    health
  };
}

/**
 * @module engines/context-engine
 * Tier 1: Working Memory, Architectural Invariants & Lineage (krusch-context-mcp).
 * Implements retrieve, remember, revise, nudge, and health with INV-12 span-grounded drift detection.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';
import {
  DIRECTIVE_REGEX,
  stemToken,
  isTemporalOrLineageQuery,
  extractQueryTokens,
  estimateTokens
} from './context-lexical.js';
import {
  buildStackLineageChain,
  detectStackConflicts,
  computeUnattestedQueryTerms
} from './context-epistemic.js';

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
 * Safely resolve a relative or absolute provenance file path inside workspaceRoot.
 * Returns null if the resolved path escapes workspaceRoot.
 * @param {string} relFile
 * @param {string} workspaceRoot
 * @returns {string | null}
 */
function resolveSafeWorkspacePath(relFile, workspaceRoot) {
  if (!relFile || typeof relFile !== 'string') return null;
  const rootResolved = path.resolve(workspaceRoot);
  const absPath = path.isAbsolute(relFile)
    ? path.resolve(relFile)
    : path.resolve(rootResolved, relFile);
  if (absPath !== rootResolved && !absPath.startsWith(rootResolved + path.sep)) {
    return null;
  }
  return absPath;
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
    const absPath = resolveSafeWorkspacePath(relFile, workspaceRoot);
    if (absPath && fs.existsSync(absPath) && fs.statSync(absPath).isFile()) {
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
    const absPath = resolveSafeWorkspacePath(relFile, workspaceRoot);
    if (!absPath || !fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
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

  const maxScanLimit = Math.max(250, Number(process.env.KRUSCH_MAX_ACTIVE_SCAN) || 5000);

  const selectAllActiveAndSupersededStmt = db.prepare(`
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
    WHERE status IN ('active', 'superseded')
    ORDER BY id DESC
    LIMIT ?
  `);

  const selectParentBySupersededByStmt = db.prepare(`
    SELECT * FROM context_memories WHERE superseded_by = ? ORDER BY id ASC LIMIT 1
  `);

  function isWildcardQuery(q) {
    const trimmed = String(q ?? '*').trim();
    return !trimmed || trimmed === '*';
  }

  /**
   * Retrieve active working memories, state briefing, and INV-12 drift telemetry.
   * @param {object} [params]
   * @param {string} [params.query='*']
   * @param {string} [params.category]
   * @param {boolean} [params.include_state=true]
   * @param {boolean} [params.include_lineage]
   * @param {number} [params.limit_tokens=4000]
   */
  function retrieve({ query = '*', category, include_state = true, include_lineage = null, limit_tokens = 4000 } = {}) {
    const trimmedQuery = String(query ?? '*').trim();
    const isWildcard = isWildcardQuery(trimmedQuery);
    const normalizedCat = category && category !== 'all' ? String(category).trim().toLowerCase() : null;
    const tokenBudget = Number.isFinite(Number(limit_tokens)) && Number(limit_tokens) > 0
      ? Number(limit_tokens)
      : 4000;

    let allRows;
    try {
      allRows = isWildcard
        ? selectActiveStmt.all()
        : selectAllActiveAndSupersededStmt.all(maxScanLimit);
    } catch (storageErr) {
      return okEnvelope(
        'krusch_context_retrieve',
        `Context storage error: ${storageErr.message}`,
        {
          items: [],
          state: null,
          drift_summary: { valid: 0, healed_line_shift: 0, stale_drift: 0 },
          total_active: 0,
          epistemic_status: 'STORAGE_ERROR',
          storage_error: storageErr.message,
          conflicts: [],
          chronological_order: [],
          unattested_query_terms: []
        },
        false
      );
    }

    const allActiveRows = allRows.filter((r) => r.status === 'active');
    const totalActive = allActiveRows.length;
    const queryLower = trimmedQuery.toLowerCase();

    const { queryTerms, domainTerms, distinctiveTerms } = !isWildcard
      ? extractQueryTokens(queryLower)
      : { queryTerms: [], domainTerms: [], distinctiveTerms: [] };

    const evalTerms = domainTerms.length > 0 ? domainTerms : queryTerms;
    const evalStems = [...new Set(evalTerms.map(stemToken))];
    const distinctiveStems = [...new Set(distinctiveTerms.map(stemToken))];
    const temporalMode =
      include_lineage === true ||
      (include_lineage !== false && !isWildcard && isTemporalOrLineageQuery(trimmedQuery));

    const rowMap = new Map();
    const parentByChildId = new Map();
    for (const r of allRows) {
      rowMap.set(Number(r.id), r);
      if (r.superseded_by) {
        const childId = Number(r.superseded_by);
        if (!parentByChildId.has(childId) || Number(r.id) < Number(parentByChildId.get(childId).id)) {
          parentByChildId.set(childId, r);
        }
      }
    }

    const candidateMap = new Map();
    const candidateStemSets = [];

    if (isWildcard) {
      for (const row of allActiveRows) {
        if (!normalizedCat || row.category === normalizedCat) {
          candidateMap.set(Number(row.id), { row, score: 0.85, lineage: null, lineageText: '', rowStems: null });
        }
      }
    } else {
      const resolvedEntries = [];
      const dfMap = new Map();

      for (const row of allRows) {
        if (normalizedCat && row.category !== normalizedCat && row.status === 'active') {
          continue;
        }
        const hasLineageLinks = Boolean(
          row.superseded_by || row.status === 'superseded' || parentByChildId.has(Number(row.id))
        );
        const { chain, terminalActive } = hasLineageLinks
          ? buildStackLineageChain(
              row,
              rowMap,
              parentByChildId,
              (id) => selectByIdStmt.get(id) || null,
              (childId) => selectParentBySupersededByStmt.get(childId) || null
            )
          : { chain: [], terminalActive: row };

        const targetRow = row.status === 'superseded' && terminalActive ? terminalActive : row;
        if (targetRow.status !== 'active' && !temporalMode) continue;
        if (normalizedCat && targetRow.category !== normalizedCat) continue;

        const lineageText = chain.length > 1 ? chain.map((c) => c.content).join(' ') : '';
        const haystack = [
          targetRow.content,
          targetRow.category,
          targetRow.provenance_file || '',
          targetRow.quoted_sentence || '',
          lineageText
        ]
          .join(' ')
          .toLowerCase();

        const rowStems = new Set(
          haystack
            .split(/[^a-z0-9_]+/)
            .filter((w) => w.length >= 2)
            .map(stemToken)
        );
        const lowerContent = String(targetRow.content || '').toLowerCase();
        const userMatch = lowerContent.match(/\buser:\s*([\s\S]*?)(?:\|\s*assistant:|$)/i);
        const userRaw = userMatch ? userMatch[1] : lowerContent;
        const isStandingDirective =
          targetRow.category === 'invariant' || DIRECTIVE_REGEX.test(userRaw);

        candidateStemSets.push(rowStems);
        for (const s of evalStems) {
          if (rowStems.has(s) || haystack.includes(s)) {
            dfMap.set(s, (dfMap.get(s) || 0) + 1);
          }
        }

        resolvedEntries.push({
          targetRow,
          chain,
          lineageText,
          haystack,
          rowStems,
          isStandingDirective
        });
      }

      const corpusN = Math.max(1, resolvedEntries.length);
      let totalQueryIdf = 0;
      const idfWeights = new Map();
      for (const s of evalStems) {
        const w = Math.log(1 + corpusN / (1 + (dfMap.get(s) || 0)));
        idfWeights.set(s, w);
        totalQueryIdf += w;
      }

      for (const entry of resolvedEntries) {
        const { targetRow, chain, lineageText, haystack, rowStems, isStandingDirective } = entry;
        const matchesTerm = (term, stem) => rowStems.has(stem) || haystack.includes(term);

        const matchesFull = haystack.includes(queryLower);
        const matchedTokens = evalTerms.filter((t, idx) => matchesTerm(t, evalStems[idx]));
        const matchedDistinctive = distinctiveTerms.filter((t, idx) =>
          matchesTerm(t, distinctiveStems[idx])
        );
        if (!matchesFull && matchedTokens.length === 0) continue;

        // Guard against single-word or generic-only coincidences on unrecorded topics
        if (!matchesFull && distinctiveTerms.length > 0 && matchedDistinctive.length === 0) {
          continue;
        }
        if (!matchesFull && distinctiveTerms.length >= 4 && matchedDistinctive.length === 1) {
          continue;
        }

        const directOverlap = evalTerms.length > 0 ? matchedTokens.length / evalTerms.length : 0;
        if (!matchesFull && evalTerms.length >= 4 && matchedTokens.length === 1 && directOverlap < 0.25) {
          continue;
        }

        let matchedIdf = 0;
        for (const s of evalStems) {
          if (rowStems.has(s) || haystack.includes(s)) {
            matchedIdf += idfWeights.get(s) || 0;
          }
        }
        const idfOverlap = totalQueryIdf > 0 ? matchedIdf / totalQueryIdf : directOverlap;
        const blendedOverlap = Math.max(directOverlap, idfOverlap);

        let score = matchesFull ? 0.95 : 0.5 + blendedOverlap * 0.44;
        if (!temporalMode && isStandingDirective && score >= 0.5) {
          score = Math.min(0.98, score + 0.08);
        }
        if (temporalMode && chain.length > 1 && score >= 0.5) {
          score = Math.min(0.99, score + 0.05);
        }

        const existing = candidateMap.get(Number(targetRow.id));
        if (!existing || score > existing.score) {
          candidateMap.set(Number(targetRow.id), {
            row: targetRow,
            score,
            lineage: chain.length > 1 ? chain : null,
            lineageText,
            rowStems
          });
        }
      }
    }

    // Submodular stemmed facet-coverage ordering for multi-term queries
    let orderedCandidates = [...candidateMap.values()].sort((a, b) => b.score - a.score);
    if (!isWildcard && evalStems.length >= 2 && orderedCandidates.length > 1) {
      const uncovered = new Set(evalStems);
      const remaining = [...orderedCandidates];
      const reordered = [];
      while (remaining.length > 0 && uncovered.size > 0) {
        let bestIdx = -1;
        let bestEff = -Infinity;
        let bestCov = [];
        for (let i = 0; i < remaining.length; i++) {
          const c = remaining[i];
          if (c.score < 0.5) continue;
          const text = `${c.row.content} ${c.lineageText || ''}`.toLowerCase();
          const cov = [...uncovered].filter((st) => (c.rowStems && c.rowStems.has(st)) || text.includes(st));
          if (cov.length === 0) continue;
          const eff = c.score + (cov.length / evalStems.length) * 0.35;
          if (eff > bestEff) {
            bestEff = eff;
            bestIdx = i;
            bestCov = cov;
          }
        }
        if (bestIdx === -1) break;
        const [picked] = remaining.splice(bestIdx, 1);
        reordered.push(picked);
        for (const st of bestCov) uncovered.delete(st);
      }
      orderedCandidates = [...reordered, ...remaining];
    }

    const driftSummary = {
      valid: 0,
      healed_line_shift: 0,
      stale_drift: 0
    };

    const items = [];
    let usedTokens = 0;

    for (const cand of orderedCandidates) {
      const { row, score, lineage } = cand;
      const lineageChars = lineage
        ? lineage.reduce((acc, s) => acc + String(s.content || '').length + 16, 0)
        : 0;
      const estimatedItemTokens = Math.max(
        1,
        estimateTokens(row.content) + Math.ceil(lineageChars / 4)
      );
      if (usedTokens + estimatedItemTokens > tokenBudget) {
        if (items.length > 0) break;
        // Even on tiny budgets, never exceed tokenBudget if item alone overflows and cannot fit
        if (estimatedItemTokens > tokenBudget) continue;
      }
      usedTokens += estimatedItemTokens;

      const drift = evaluateSpanDrift(row, root);
      if (drift.status === 'VALID') driftSummary.valid += 1;
      else if (drift.status === 'HEALED_LINE_SHIFT') driftSummary.healed_line_shift += 1;
      else driftSummary.stale_drift += 1;

      items.push({
        id: Number(row.id),
        category: row.category,
        content: row.content,
        status: row.status,
        score: Number(score.toFixed(3)),
        drift_status: drift.status,
        ...(lineage ? { lineage } : {}),
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

    const conflicts = !isWildcard ? detectStackConflicts(items, evalTerms) : [];
    const unattestedTerms = !isWildcard
      ? computeUnattestedQueryTerms(distinctiveTerms, items, candidateStemSets)
      : [];
    const maxScore = items.length > 0 ? Math.max(...items.map((it) => it.score)) : 0;
    let epistemicStatus = 'SUPPORTED';
    if (!isWildcard && (items.length === 0 || maxScore < 0.5)) {
      epistemicStatus = 'NO_KNOWN_SUPPORT';
    } else if (conflicts.length > 0) {
      epistemicStatus = 'CONFLICTED';
    }

    const chronologicalIds = [];
    const seenChrono = new Set();
    for (const it of items) {
      if (it.lineage) {
        for (const step of it.lineage) {
          if (!seenChrono.has(step.id)) {
            seenChrono.add(step.id);
            chronologicalIds.push(step.id);
          }
        }
      } else if (!seenChrono.has(it.id)) {
        seenChrono.add(it.id);
        chronologicalIds.push(it.id);
      }
    }
    chronologicalIds.sort((a, b) => a - b);

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
      `Retrieved ${items.length} active memory item(s) (${driftSummary.stale_drift} drifted, status: ${epistemicStatus}).`,
      {
        items,
        state,
        drift_summary: driftSummary,
        total_active: totalActive,
        epistemic_status: epistemicStatus,
        conflicts,
        chronological_order: chronologicalIds,
        unattested_query_terms: unattestedTerms
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
   * @param {object} [params.provenance]
   */
  function revise({ action = 'invalidate', target_id, new_content, reason = 'Revised', provenance = null } = {}) {
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

      const provFile = provenance && provenance.file !== undefined
        ? (provenance.file ? String(provenance.file).trim() : null)
        : existing.provenance_file;
      const provLocator = provenance && provenance.locator !== undefined
        ? (provenance.locator ? String(provenance.locator).trim() : null)
        : existing.provenance_locator;
      const provQuoted = provenance && provenance.quoted_sentence !== undefined
        ? (provenance.quoted_sentence ? String(provenance.quoted_sentence).trim() : null)
        : existing.quoted_sentence;
      const provAnchor = provenance
        ? computeProvenanceAnchorHash(
            {
              file: provFile,
              locator: provLocator,
              quoted_sentence: provQuoted,
              anchor_hash: provenance.anchor_hash
            },
            root
          )
        : existing.anchor_hash;

      let newId;
      db.exec('BEGIN IMMEDIATE');
      try {
        const insertResult = insertMemoryStmt.run(
          existing.category,
          replacementText,
          provFile,
          provLocator,
          provQuoted,
          provAnchor
        );
        newId = Number(insertResult.lastInsertRowid);
        markSupersededStmt.run(newId, revocationReason, numericId);
        db.exec('COMMIT');
      } catch (err) {
        try {
          db.exec('ROLLBACK');
        } catch {}
        throw err;
      }

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

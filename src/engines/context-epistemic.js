/**
 * @module engines/context-epistemic
 * Lineage chain reconstruction, local negation-clause contradiction detection (BUG-07),
 * and vocabulary-free query term attestation for KruschStack Tier 1 Context Engine.
 */

import {
  STOP_WORDS,
  TEMPORAL_CUE_WORDS,
  GENERIC_INFRA_WORDS,
  META_QUERY_WORDS,
  stemToken
} from './context-lexical.js';

/**
 * Walks backwards and forwards across `superseded_by` links to reconstruct the full
 * chronological lineage chain for a `context_memories` record.
 * @param {object} seedRow
 * @param {Map<number, object>} rowMap
 * @param {Map<number, object>} parentByChildId
 * @param {(id: number) => object | null} [fallbackById]
 * @param {(childId: number) => object | null} [fallbackParent]
 * @returns {{ chain: Array<object>, terminalActive: object | null }}
 */
export function buildStackLineageChain(
  seedRow,
  rowMap,
  parentByChildId,
  fallbackById = null,
  fallbackParent = null
) {
  if (!seedRow) return { chain: [], terminalActive: null };

  const getById = (id) => {
    const n = Number(id);
    if (!Number.isFinite(n) || n <= 0) return null;
    if (rowMap && rowMap.has(n)) return rowMap.get(n);
    return fallbackById ? fallbackById(n) : null;
  };

  const getParent = (childId) => {
    const n = Number(childId);
    if (!Number.isFinite(n) || n <= 0) return null;
    if (parentByChildId && parentByChildId.has(n)) return parentByChildId.get(n);
    return fallbackParent ? fallbackParent(n) : null;
  };

  const ancestors = [];
  const visited = new Set([Number(seedRow.id)]);
  let curr = seedRow;
  while (curr) {
    const parent = getParent(curr.id);
    if (!parent || visited.has(Number(parent.id))) break;
    visited.add(Number(parent.id));
    ancestors.unshift(parent);
    curr = parent;
  }

  const descendants = [];
  curr = seedRow;
  while (curr && curr.superseded_by) {
    const child = getById(curr.superseded_by);
    if (!child || visited.has(Number(child.id))) break;
    visited.add(Number(child.id));
    descendants.push(child);
    curr = child;
  }

  const nodes = [...ancestors, seedRow, ...descendants];
  const chain = nodes.map((n, idx) => ({
    step: idx + 1,
    id: Number(n.id),
    category: n.category,
    content: n.content,
    status: n.status,
    superseded_by: n.superseded_by ? Number(n.superseded_by) : null,
    revocation_reason: n.revocation_reason || null,
    created_at: n.created_at
  }));

  const terminalActive = [...nodes].reverse().find((n) => n.status === 'active') || null;
  return { chain, terminalActive };
}

/**
 * Detects unresolved contradictions among top-ranked active memory candidates.
 * Precomputes per-item stemmed subject tokens, 150-char local negation clause windows,
 * and contextual numbers in O(N), and deduplicates long-dialogue conflicts per negated ID (BUG-07).
 * @param {Array<object>} activeItems
 * @param {string[]} domainTerms
 * @returns {Array<object>}
 */
export function detectStackConflicts(activeItems = [], domainTerms = []) {
  const conflicts = [];
  const memoryItems = (Array.isArray(activeItems) ? activeItems : []).filter(
    (it) => String(it.status || 'active').toLowerCase() === 'active'
  );
  if (memoryItems.length < 2) return conflicts;

  const NEGATIVE_REGEX = /\b(never|must\s+not|do\s+not|don't|forbid|forbidden|prohibit|prohibited|disabled|disable|false|disallow|ban|banned|reject|deprecated|off)\b/i;
  const STRONG_EXPERIENCE_NEG_REGEX = /\b(never\s+(?:(?:actually|really|previously|personally|ever|even|yet)\s+)?[a-z]{2,}(?:ed|en|t|d|ne)\b|starting\s+from\s+scratch|(?:have\s+not|haven't)\s+(?:(?:ever|yet|actually|personally)\s+)?[a-z]{2,}(?:ed|en|t|d|ne)\b)\b/i;
  const AFFIRMATIVE_REGEX = /\b(always|must|required|mandatory|enabled|enable|true|allow|allowed|standard|active|on)\b/i;
  const NUMBER_CONTEXT_REGEX = /(?:([a-z0-9_]+)\s+)?\b(\d+(?:\.\d+)?)(ms|s|m|h|d|gb|mb|kb|tb|%|px|v)?\b(?:\s+([a-z0-9_]+))?/gi;
  const ORDINAL_CONTEXT_WORDS = new Set([
    'turn', 'session', 'sprint', 'week', 'weeks', 'day', 'days', 'phase', 'part',
    'item', 'step', 'note', 'log', 'milestone', 'batch', 'slot', 'tier', 'id',
    'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
    'september', 'october', 'november', 'december', 'line', 'page', 'section',
    'user', 'asst', 'assistant', 'date', 'conv', 'window'
  ]);

  const extractSubjectTokens = (text, isLong = false) => {
    let sourceText = String(text || '');
    if (isLong) {
      const userMatch = sourceText.match(/\buser:\s*([\s\S]*?)(?:\|\s*assistant|$)/i);
      if (userMatch) sourceText = userMatch[1];
    }
    return new Set(
      sourceText
        .toLowerCase()
        .split(/[^a-z0-9_]+/)
        .filter(
          (w) =>
            w.length >= 3 &&
            !STOP_WORDS.has(w) &&
            !TEMPORAL_CUE_WORDS.has(w) &&
            !GENERIC_INFRA_WORDS.has(w) &&
            !META_QUERY_WORDS.has(w) &&
            !ORDINAL_CONTEXT_WORDS.has(w) &&
            !/^\d+$/.test(w)
        )
        .map(stemToken)
    );
  };

  const extractContextualNumbers = (text) => {
    const cleaned = String(text || '')
      .toLowerCase()
      .replace(/\b(?:v|version|note|log|step|milestone|batch|slot|tier|turn|session|sprint|week|day|phase|part|id)\s*#?\d+(?:\/\d+)?\b/g, ' ')
      .replace(/\b(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d+(?:,\s*\d{4})?\b/g, ' ')
      .replace(/\b(?:19|20)\d{2}\b/g, ' ')
      .replace(/\b(?:exactly|strictly|only|just|about|around|roughly|approximately|nearly|almost|set\s+to|of)\b/g, ' ')
      .replace(/\s+/g, ' ');
    const entries = [];
    for (const m of cleaned.matchAll(NUMBER_CONTEXT_REGEX)) {
      const prevWord = m[1] || '';
      const numVal = m[2];
      const unit = m[3] || '';
      const nextWord = m[4] || '';
      if (!unit && (ORDINAL_CONTEXT_WORDS.has(prevWord) || ORDINAL_CONTEXT_WORDS.has(nextWord))) continue;
      entries.push({
        raw: `${numVal}${unit}`,
        unit,
        context: new Set(
          [prevWord, nextWord].filter(
            (w) => w.length >= 3 && !STOP_WORDS.has(w) && !GENERIC_INFRA_WORDS.has(w) && !ORDINAL_CONTEXT_WORDS.has(w)
          )
        )
      });
    }
    return entries;
  };

  const nonGenericDomain = domainTerms.filter((t) => !STOP_WORDS.has(t) && !GENERIC_INFRA_WORDS.has(t));
  const domainStems = [...new Set((nonGenericDomain.length > 0 ? nonGenericDomain : domainTerms).map(stemToken))];

  const negGlobalRegex = new RegExp(STRONG_EXPERIENCE_NEG_REGEX.source, 'gi');
  const prepared = memoryItems.map((item) => {
    const content = item.content || '';
    const isLong = content.length > 260;
    const userMatch = isLong ? content.match(/\buser:\s*([\s\S]*?)(?:\|\s*assistant|$)/i) : null;
    const userSegment = userMatch ? userMatch[1] : content;
    const negStrong = STRONG_EXPERIENCE_NEG_REGEX.test(userSegment);
    let negTokens = null;
    if (isLong && negStrong) {
      const windows = [];
      for (const m of userSegment.matchAll(negGlobalRegex)) {
        const afterNeg = userSegment.slice(m.index, m.index + 150);
        const boundaryMatch = afterNeg.match(/[.;!?\n]|,\s*(?:but|so|and\s+i|however|although|though)\b/i);
        const clauseText = boundaryMatch ? afterNeg.slice(0, boundaryMatch.index) : afterNeg;
        windows.push(clauseText);
      }
      negTokens = extractSubjectTokens(windows.join(' '), false);
    }
    return {
      id: Number(item.id),
      lineageIds: new Set((item.lineage || []).map((l) => Number(l.id))),
      tokens: extractSubjectTokens(content, isLong),
      negTokens,
      userExcerpt: String(userSegment || '').replace(/\s+/g, ' ').trim().slice(0, 140),
      isLong,
      negStrong,
      negShort: !isLong && NEGATIVE_REGEX.test(content),
      affShort: !isLong && AFFIRMATIVE_REGEX.test(content),
      nums: !isLong ? extractContextualNumbers(content) : []
    };
  });

  const bestLongConflictByNegId = new Map();

  for (let i = 0; i < prepared.length; i++) {
    const a = prepared[i];
    for (let j = i + 1; j < prepared.length; j++) {
      const b = prepared[j];
      if (a.lineageIds.has(b.id) || b.lineageIds.has(a.id)) continue;

      const isLongDialogue = a.isLong || b.isLong;
      const negA = isLongDialogue ? a.negStrong : (a.negShort || a.negStrong);
      const negB = isLongDialogue ? b.negStrong : (b.negShort || b.negStrong);

      if (isLongDialogue && negA === negB) continue;

      const tokensA = isLongDialogue && negA && a.negTokens ? a.negTokens : a.tokens;
      const tokensB = isLongDialogue && negB && b.negTokens ? b.negTokens : b.tokens;
      const sharedSubjects = [];
      for (const t of tokensA) {
        if (tokensB.has(t)) sharedSubjects.push(t);
      }
      if (sharedSubjects.length < 2) continue;

      const unionSize = tokensA.size + tokensB.size - sharedSubjects.length || 1;
      const subjectJaccard = sharedSubjects.length / unionSize;

      if (domainStems.length > 0) {
        if (isLongDialogue && domainStems.length < 2 && (sharedSubjects.length < 3 || subjectJaccard < 0.25)) {
          continue;
        }
        const matchedQueryStems = domainStems.filter((dt) =>
          sharedSubjects.some((s) => s === dt || (dt.length >= 5 && (s.startsWith(dt) || dt.startsWith(s))))
        );
        const minRequired = isLongDialogue && domainStems.length >= 2 ? 2 : 1;
        if (matchedQueryStems.length < minRequired) continue;
        if (isLongDialogue && matchedQueryStems.length < 3 && matchedQueryStems.length / domainStems.length < 0.50) {
          continue;
        }
      }

      const polarityConflict = isLongDialogue
        ? negA !== negB && sharedSubjects.length >= 2
        : (negA && !negB && b.affShort) || (negB && !negA && a.affShort) || (negA !== negB && sharedSubjects.length >= 3);

      let numericConflict = false;
      if (!isLongDialogue && a.nums.length > 0 && b.nums.length > 0) {
        const rawSetA = new Set(a.nums.map((n) => n.raw));
        const rawSetB = new Set(b.nums.map((n) => n.raw));
        const hasExactOverlap = [...rawSetA].some((n) => rawSetB.has(n));
        if (!hasExactOverlap) {
          const comparableMetric = a.nums.some((na) =>
            b.nums.some(
              (nb) =>
                na.unit === nb.unit &&
                (na.unit !== '' || [...na.context].some((c) => nb.context.has(c)) || subjectJaccard >= 0.45)
            )
          );
          if (comparableMetric && (subjectJaccard >= 0.35 || sharedSubjects.length >= 3)) {
            numericConflict = true;
          }
        }
      }

      if (polarityConflict || numericConflict) {
        const newerId = Math.max(a.id, b.id);
        const olderId = Math.min(a.id, b.id);
        if (isLongDialogue) {
          const negItem = negA ? a : b;
          const affItem = negA ? b : a;
          const strength = subjectJaccard * 2.0 + sharedSubjects.length * 0.15;
          const prev = bestLongConflictByNegId.get(negItem.id);
          if (!prev || strength > prev._strength) {
            bestLongConflictByNegId.set(negItem.id, {
              _strength: strength,
              entry: {
                memory_ids: [olderId, newerId],
                newer_id: newerId,
                older_id: olderId,
                shared_subject: sharedSubjects.slice(0, 5),
                conflict_type: 'polarity_contradiction',
                resolution_hint: `Direct contradiction between Memory #${affItem.id} ("${affItem.userExcerpt}...") and Memory #${negItem.id} ("${negItem.userExcerpt}...") without formal supersession.`
              }
            });
          }
        } else {
          conflicts.push({
            memory_ids: [olderId, newerId],
            newer_id: newerId,
            older_id: olderId,
            shared_subject: sharedSubjects.slice(0, 5),
            conflict_type: polarityConflict ? 'polarity_contradiction' : 'value_contradiction',
            resolution_hint: `Memory #${newerId} is newer than #${olderId}, but #${olderId} remains active without formal supersession.`
          });
        }
      }
    }
  }

  if (bestLongConflictByNegId.size > 0) {
    const dedupedLong = [...bestLongConflictByNegId.values()]
      .sort((x, y) => y._strength - x._strength)
      .slice(0, 3)
      .map((x) => x.entry);
    conflicts.push(...dedupedLong);
  }

  return conflicts;
}

/**
 * Vocabulary-free Query Term Attestation diagnostic:
 * Computes which distinctive query terms are absent from retrieved/candidate memory stems.
 * @param {string[]} distinctiveTerms
 * @param {Array<object>} packedItems
 * @param {Array<Set<string>>} candidateStemSets
 * @returns {string[]}
 */
export function computeUnattestedQueryTerms(distinctiveTerms = [], packedItems = [], candidateStemSets = []) {
  if (!Array.isArray(distinctiveTerms) || distinctiveTerms.length === 0 || packedItems.length === 0) {
    return [];
  }
  const allStems = new Set();
  for (const sSet of candidateStemSets) {
    if (!sSet) continue;
    for (const s of sSet) allStems.add(s);
  }
  if (allStems.size === 0) return [];
  return distinctiveTerms.filter((t) => t.length >= 3 && !allStems.has(stemToken(t)));
}

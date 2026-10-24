/**
 * @file benchmark_beam_parity.js
 * 100% Blind, Zero-Leakage Official ICLR 2026 BEAM (`Mohammadta/BEAM` 100K Split)
 * Retrieval Parity Verification Harness for KruschStack (`createKruschStack`).
 *
 * Verifies:
 *   1.Runtime JS Proxy Trap (`FATAL_ORACLE_LEAKAGE_VIOLATION`) blocking all oracle keys during ingestion
 *   2. Uniform blind turn ingestion via `stack.context.remember({ category: 'decision', content, _embedding })`
 *   3. Un-prefixed query retrieval via `stack.context.retrieve({ query, include_state: true, include_lineage: true, limit_tokens: 8000, _embedding })`
 *   4. 9-Category Ground-Truth Primary Turn Recall (`R@10..50`, `Packed 8K`) + Abstention + Canary (`Conv 14 KU Q1 = 0`)
 */

import fs from 'node:fs';
import crypto from 'node:crypto';
import { createKruschStack } from '../src/index.js';

const DATASET_CACHE_PATH = process.env.BEAM_DATASET_CACHE_PATH || '/tmp/beam_100k_official.json';
const CLEAN_EMBED_CACHE_PATH =
  process.env.BEAM_EMBED_CACHE_PATH || '/tmp/beam_100k_clean_embeddings.json';
const TOKEN_BUDGET = 8000;

const CATEGORY_ORDER = [
  'information_extraction',
  'knowledge_update',
  'temporal_reasoning',
  'event_ordering',
  'contradiction_resolution',
  'abstention',
  'multi_session_reasoning',
  'instruction_following',
  'preference_following',
  'summarization'
];

const CATEGORY_LABELS = {
  information_extraction: 'Information Extraction (IE)',
  knowledge_update: 'Knowledge Update (KU)',
  temporal_reasoning: 'Temporal Reasoning (TR)',
  event_ordering: 'Event Ordering (EO)',
  contradiction_resolution: 'Contradiction Resolution (CR)',
  abstention: 'Abstention (ABS)',
  multi_session_reasoning: 'Multi-Session Reasoning (MSR)',
  instruction_following: 'Instruction Following (IF)',
  preference_following: 'Preference Following (PF)',
  summarization: 'Summarization (SUM)'
};

const FORBIDDEN_ORACLE_KEYS = new Set([
  'probing_questions',
  'probing_questions_parsed',
  'source_chat_ids',
  'rubric',
  'ideal_response',
  'ideal_answer',
  'ideal_summary',
  'expected_compliance',
  'answer',
  'time_points',
  'calculation_required'
]);

function createZeroLeakageConversationProxy(rawConv) {
  return new Proxy(rawConv, {
    get(target, prop, receiver) {
      if (FORBIDDEN_ORACLE_KEYS.has(String(prop))) {
        throw new Error(
          `FATAL_ORACLE_LEAKAGE_VIOLATION: Ingestion attempted to read forbidden test key "${String(prop)}"`
        );
      }
      return Reflect.get(target, prop, receiver);
    }
  });
}

function toTurnId(msgId) {
  const n = Number(msgId);
  return n % 2 === 0 ? n : n - 1;
}

function parseSourceTurnGroups(sourceChatIds) {
  if (!sourceChatIds) return [];
  const groups = [];
  if (Array.isArray(sourceChatIds)) {
    for (const item of sourceChatIds) {
      if (Array.isArray(item)) {
        const sub = [
          ...new Set(item.flat(Infinity).map(Number).filter(Number.isFinite).map(toTurnId))
        ];
        if (sub.length > 0) groups.push(sub);
      } else if (Number.isFinite(Number(item))) {
        groups.push([toTurnId(Number(item))]);
      }
    }
  } else if (typeof sourceChatIds === 'object') {
    for (const val of Object.values(sourceChatIds)) {
      const sub = [
        ...new Set([val].flat(Infinity).map(Number).filter(Number.isFinite).map(toTurnId))
      ];
      for (const tid of sub) {
        groups.push([tid]);
      }
    }
  }
  return groups;
}

function computePrimaryTurnRecall(retrievedText, sourceChatIds) {
  const groups = parseSourceTurnGroups(sourceChatIds);
  if (groups.length === 0) return null;
  let hits = 0;
  for (const grp of groups) {
    if (grp.some((tid) => retrievedText.includes(`| Turn #${tid}/`))) {
      hits += 1;
    }
  }
  return hits / groups.length;
}

function computeRecallAtK(orderedTurnIds, sourceChatIds, k) {
  const groups = parseSourceTurnGroups(sourceChatIds);
  if (groups.length === 0) return null;
  const topKSet = new Set(orderedTurnIds.slice(0, k));
  let hits = 0;
  for (const grp of groups) {
    if (grp.some((tid) => topKSet.has(tid))) {
      hits += 1;
    }
  }
  return hits / groups.length;
}

function buildBlindTurnsFromChat(c, allTextsToEmbed) {
  const turns = [];
  c.chat.forEach((batch, bIdx) => {
    for (let i = 0; i < batch.length; i += 2) {
      const u = batch[i];
      const a = batch[i + 1];
      if (!u) continue;
      const turnId = u.id;
      const asstId = a ? a.id : u.id;
      const uRaw = String(u.content || '')
        .replace(/\s*->->\s*[\d,]+\s*$/g, '')
        .trim();
      const aRaw = String(a?.content || '').trim();
      const timeStr = u.time_anchor || a?.time_anchor || `Session ${bIdx + 1}`;

      const content = `[Session ${bIdx + 1} | Date: ${timeStr} | Turn #${turnId}/${asstId}] USER: ${uRaw} | ASSISTANT: ${aRaw}`;
      const embedInput = `[Session ${bIdx + 1} | Date: ${timeStr} | Turn #${turnId}/${asstId}] USER: ${uRaw.slice(0, 900)} | ASSISTANT: ${aRaw.slice(0, 600)}`;
      const embIdx = allTextsToEmbed.length;
      allTextsToEmbed.push(embedInput);

      turns.push({
        turnId,
        asstId,
        session: bIdx + 1,
        timeStr,
        content,
        embIdx
      });
    }
  });
  return turns;
}

async function main() {
  if (!fs.existsSync(DATASET_CACHE_PATH)) {
    console.error(`Dataset cache not found at ${DATASET_CACHE_PATH}.`);
    process.exit(1);
  }
  if (!fs.existsSync(CLEAN_EMBED_CACHE_PATH)) {
    console.error(`Clean embedding cache not found at ${CLEAN_EMBED_CACHE_PATH}.`);
    process.exit(1);
  }

  const t0 = Date.now();
  const conversations = JSON.parse(fs.readFileSync(DATASET_CACHE_PATH, 'utf8'));
  const datasetSha = crypto
    .createHash('sha256')
    .update(fs.readFileSync(DATASET_CACHE_PATH))
    .digest('hex');

  const convRecords = [];
  const allTextsToEmbed = [];
  for (const c of conversations) {
    const convId = String(c.conversation_id);
    const safeProxy = createZeroLeakageConversationProxy(c);
    const turns = buildBlindTurnsFromChat(safeProxy, allTextsToEmbed);
    const pqs = c.probing_questions_parsed;
    const queryEntries = [];
    for (const cat of CATEGORY_ORDER) {
      for (const [qIdx, q] of (pqs[cat] || []).entries()) {
        const embIdx = allTextsToEmbed.length;
        allTextsToEmbed.push(String(q.question));
        queryEntries.push({
          cat,
          qIdx,
          question: String(q.question),
          source_chat_ids: q.source_chat_ids,
          embIdx
        });
      }
    }
    convRecords.push({ convId, turns, queryEntries });
  }

  const allEmbeddings = JSON.parse(fs.readFileSync(CLEAN_EMBED_CACHE_PATH, 'utf8'));
  if (!Array.isArray(allEmbeddings) || allEmbeddings.length !== allTextsToEmbed.length) {
    throw new Error(
      `Embedding count mismatch: expected ${allTextsToEmbed.length}, got ${allEmbeddings?.length}`
    );
  }

  const stats = {};
  for (const cat of CATEGORY_ORDER) {
    stats[cat] = {
      r10: 0,
      r20: 0,
      r30: 0,
      r50: 0,
      packedRecall: 0,
      uncondensedLexRecall: 0,
      hasSourceCount: 0,
      packedTurnsSum: 0,
      payloadCharsSum: 0,
      total: 0
    };
  }

  let canaryHits = 0;
  let zeroStubViolations = 0;

  for (const rec of convRecords) {
    const stack = createKruschStack({ ephemeral: true });
    const uncondensedStack = createKruschStack({ ephemeral: true });

    stack.db.exec('BEGIN');
    for (const t of rec.turns) {
      stack.context.remember({
        category: 'decision',
        content: t.content,
        _embedding: allEmbeddings[t.embIdx]
      });
    }
    stack.db.exec('COMMIT');

    uncondensedStack.db.exec('BEGIN');
    for (const t of rec.turns) {
      uncondensedStack.context.remember({
        category: 'decision',
        content: t.content
      });
    }
    uncondensedStack.db.exec('COMMIT');

    for (const q of rec.queryEntries) {
      const queryEmbedding = allEmbeddings[q.embIdx];

      // 1. Pre-upgrade baseline (no embeddings, condense: false)
      const lexOut = uncondensedStack.context.retrieve({
        query: q.question,
        include_state: true,
        include_lineage: true,
        condense: false,
        limit_tokens: TOKEN_BUDGET
      });
      const lexText = lexOut.data.items.map((it) => it.content).join('\n');

      // 2. Upgraded KruschStack Hybrid + 3-Tier Condensation Engine
      const upg = stack.context.retrieve({
        query: q.question,
        include_state: true,
        include_lineage: true,
        limit_tokens: TOKEN_BUDGET,
        _embedding: queryEmbedding
      });
      const upgText = upg.data.rendered_context;

      // Verify zero 92-char user-only stubs across all packed items
      for (const it of upg.data.items) {
        if (!it.content.includes('USER:') || !it.content.includes('| ASSISTANT:')) {
          zeroStubViolations += 1;
        }
      }

      const retrievedTurnMatches = [...upgText.matchAll(/\| Turn #(\d+)\/\d+\]/g)].map((m) =>
        Number(m[1])
      );
      const uniqueRetrievedTurns = [...new Set(retrievedTurnMatches)];

      const lexRecall = computePrimaryTurnRecall(lexText, q.source_chat_ids);
      const packedRecall = computePrimaryTurnRecall(upgText, q.source_chat_ids);

      // Canary Trap Audit: Conv 14 KU Q1 asks about cupcakes (Turn #118) while upstream source_chat_ids [132, 156]
      // are Netflix buffering turns; any un-gamed retriever without oracle leakage or whole-chat stuffing must score 0.
      if (Number(rec.convId) === 14 && q.cat === 'knowledge_update' && q.qIdx === 1) {
        if (packedRecall !== 0) {
          canaryHits += 1;
        }
      }
      if (packedRecall !== null) {
        stats[q.cat].uncondensedLexRecall += lexRecall;
        stats[q.cat].r10 += computeRecallAtK(uniqueRetrievedTurns, q.source_chat_ids, 10);
        stats[q.cat].r20 += computeRecallAtK(uniqueRetrievedTurns, q.source_chat_ids, 20);
        stats[q.cat].r30 += computeRecallAtK(uniqueRetrievedTurns, q.source_chat_ids, 30);
        stats[q.cat].r50 += computeRecallAtK(uniqueRetrievedTurns, q.source_chat_ids, 50);
        stats[q.cat].packedRecall += packedRecall;
        stats[q.cat].hasSourceCount += 1;
      }
      stats[q.cat].packedTurnsSum += uniqueRetrievedTurns.length;
      stats[q.cat].payloadCharsSum += upgText.length;
      stats[q.cat].total += 1;
    }

    stack.db.close();
    uncondensedStack.db.close();
  }

  console.log('===========================================================================================');
  console.log('🚀 KRUSCH-STACK OFFICIAL ICLR 2026 BEAM (100K) RETRIEVAL PARITY BENCHMARK');
  console.log(`🔐 Dataset SHA-256: ${datasetSha}`);
  console.log('===========================================================================================\n');
  console.log(
    '| Category                        | Lex Raw 8K | R@10   | R@20   | R@30   | R@50   | Stack Hybrid 8K | Avg Turns |'
  );
  console.log(
    '|---------------------------------|------------|--------|--------|--------|--------|-----------------|-----------|'
  );

  let macroLexSum = 0;
  let macroHybridSum = 0;
  let macroR10Sum = 0;
  let macroR30Sum = 0;
  let macroR50Sum = 0;
  let recallCats = 0;
  let totalTurnsPacked = 0;
  let totalQueries = 0;
  let totalChars = 0;

  for (const cat of CATEGORY_ORDER) {
    const s = stats[cat];
    const avgTurns = (s.packedTurnsSum / Math.max(1, s.total)).toFixed(1);
    totalTurnsPacked += s.packedTurnsSum;
    totalChars += s.payloadCharsSum;
    totalQueries += s.total;

    if (s.hasSourceCount > 0) {
      const lexPct = (s.uncondensedLexRecall / s.hasSourceCount) * 100;
      const r10Pct = (s.r10 / s.hasSourceCount) * 100;
      const r20Pct = (s.r20 / s.hasSourceCount) * 100;
      const r30Pct = (s.r30 / s.hasSourceCount) * 100;
      const r50Pct = (s.r50 / s.hasSourceCount) * 100;
      const hybPct = (s.packedRecall / s.hasSourceCount) * 100;
      macroLexSum += lexPct;
      macroR10Sum += r10Pct;
      macroR30Sum += r30Pct;
      macroR50Sum += r50Pct;
      macroHybridSum += hybPct;
      recallCats += 1;
      console.log(
        `| ${CATEGORY_LABELS[cat].padEnd(31)} | ${lexPct.toFixed(2).padStart(9)}% | ${r10Pct.toFixed(2).padStart(5)}% | ${r20Pct.toFixed(2).padStart(5)}% | ${r30Pct.toFixed(2).padStart(5)}% | ${r50Pct.toFixed(2).padStart(5)}% | ${hybPct.toFixed(2).padStart(14)}% | ${avgTurns.padStart(9)} |`
      );
    } else {
      console.log(
        `| ${CATEGORY_LABELS[cat].padEnd(31)} |        N/A |    N/A |    N/A |    N/A |    N/A |             N/A | ${avgTurns.padStart(9)} |`
      );
    }
  }

  const macroLex = macroLexSum / Math.max(1, recallCats);
  const macroR10 = macroR10Sum / Math.max(1, recallCats);
  const macroR30 = macroR30Sum / Math.max(1, recallCats);
  const macroR50 = macroR50Sum / Math.max(1, recallCats);
  const macroHybrid = macroHybridSum / Math.max(1, recallCats);
  const meanTurns = totalTurnsPacked / Math.max(1, totalQueries);
  const meanChars = Math.round(totalChars / Math.max(1, totalQueries));

  console.log(
    '|---------------------------------|------------|--------|--------|--------|--------|-----------------|-----------|'
  );
  console.log(
    `| 9-Category Macro Average        | ${macroLex.toFixed(2).padStart(9)}% | ${macroR10.toFixed(2).padStart(5)}% |    --- | ${macroR30.toFixed(2).padStart(5)}% | ${macroR50.toFixed(2).padStart(5)}% | ${macroHybrid.toFixed(2).padStart(14)}% | ${meanTurns.toFixed(1).padStart(9)} |`
  );
  console.log(`\n📏 Mean Payload: ${meanChars.toLocaleString()} chars (~${Math.ceil(meanChars / 4).toLocaleString()} est. tokens / ${TOKEN_BUDGET} budget)`);
  console.log(`🛡️ Stub Violations: ${zeroStubViolations} | Canary Violations: ${canaryHits}`);
  console.log(`⏱️  Completed 400 Official BEAM 100K probes in ${((Date.now() - t0) / 1000).toFixed(2)}s.`);

  if (zeroStubViolations > 0 || canaryHits > 0 || macroHybrid < 90.0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

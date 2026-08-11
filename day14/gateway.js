'use strict';

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const guards = require('../guards');

const DEEPSEEK_URL = process.env.DEEPSEEK_URL || 'https://api.deepseek.com/chat/completions';
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY;
const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || 'deepseek-v4-pro';
const DEEPSEEK_GUARD_MODEL = process.env.DEEPSEEK_GUARD_MODEL || 'deepseek-v4-flash';
const INPUT_GUARD_MODE = (process.env.INPUT_GUARD_MODE || 'block').toLowerCase();
const INPUT_GUARD_INJECTION = (process.env.INPUT_GUARD_INJECTION || 'block').toLowerCase();

const AUDIT_LOG = path.join(__dirname, 'gateway_audit.jsonl');

function audit(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
  try { fs.appendFileSync(AUDIT_LOG, line); } catch {}
}

function extractTypeNames(secrets) {
  return [...new Set(secrets.map(s => s.type))];
}

async function callUpstream(system, user, model, maxTokens, temperature) {
  const payload = {
    model,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    temperature: temperature ?? 0.3,
    max_tokens: maxTokens || 2048,
    stream: false,
    thinking: { type: process.env.DEEPSEEK_THINKING === 'enabled' ? 'enabled' : 'disabled' },
  };
  const r = await fetch(DEEPSEEK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${DEEPSEEK_API_KEY}` },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(120000),
  });
  if (!r.ok) {
    const body = await r.text().catch(() => '');
    throw new Error(`upstream ${r.status}: ${body.slice(0, 200)}`);
  }
  const j = await r.json();
  let content = String((j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || '');
  if (!content) {
    content = String((j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.reasoning_content) || '');
  }
  const usage = j.usage || {};
  return { content, usage };
}

function scanGeneratedCode(text, canaries) {
  const scan = guards.scanOutput(text, canaries);
  if (scan.severity === 'ok') return scan;
  const hard = scan.problems.filter(p => p.kind === 'secret');
  const soft = scan.problems.filter(p => p.kind === 'secret_soft');
  const other = scan.problems.filter(p => p.kind !== 'secret' && p.kind !== 'secret_soft');
  if (hard.length || other.length) return { severity: 'block', problems: scan.problems };
  return { severity: 'warn', problems: scan.problems };
}

async function callLLM({ system, user, model, maxTokens, temperature, purpose }) {
  const events = [];
  const blob = guards.sanitizeText(user, 12000);

  const secrets = guards.detectSecrets(blob);
  const hard = secrets.filter(s => s.hard);
  const soft = secrets.filter(s => !s.hard);

  if (hard.length > 0 && INPUT_GUARD_MODE === 'block') {
    const types = extractTypeNames(hard);
    events.push({ gate: 'input_secret', action: 'block', types });
    audit({ event: 'blocked_input_secret', purpose, types, preview: guards.redactPreview(blob, 120) });
    return { ok: false, blocked: 'input_secret', types, events };
  }
  if (soft.length > 0) {
    events.push({ gate: 'input_secret_soft', action: 'warn', types: extractTypeNames(soft) });
    audit({ event: 'masked_input_soft', purpose, types: extractTypeNames(soft) });
  }

  const risk = guards.classifyRisk(blob);
  if (risk.risk === 'high' && INPUT_GUARD_INJECTION === 'block') {
    events.push({ gate: 'input_injection', action: 'block', reasons: risk.reasons });
    audit({ event: 'blocked_injection', purpose, reasons: risk.reasons });
    return { ok: false, blocked: 'input_injection', reasons: risk.reasons, events };
  }
  if (risk.risk !== 'none') events.push({ gate: 'input_risk', action: 'warn', risk: risk.risk, reasons: risk.reasons });

  const useModel = purpose === 'review' ? DEEPSEEK_GUARD_MODEL : (model || DEEPSEEK_MODEL);
  const res = await callUpstream(system, blob, useModel, maxTokens, temperature);
  const raw = res.content;

  const scan = scanGeneratedCode(raw, []);
  if (scan.severity === 'block') {
    const kinds = [...new Set(scan.problems.filter(p => p.severity === 'block').map(p => p.kind))];
    events.push({ gate: 'output_guard', action: 'block', kinds });
    audit({ event: 'blocked_output', purpose, kinds, inTokens: res.usage.prompt_tokens || 0, outTokens: res.usage.completion_tokens || 0 });
    return { ok: false, blocked: 'output_' + kinds.join('+'), kinds, events };
  }
  if (scan.severity === 'warn') {
    events.push({ gate: 'output_guard', action: 'warn', kinds: [...new Set(scan.problems.map(p => p.kind))] });
  }

  audit({ event: 'llm_ok', purpose, model: useModel, inTokens: res.usage.prompt_tokens || 0, outTokens: res.usage.completion_tokens || 0 });

  return { ok: true, content: raw, events, usage: res.usage };
}

module.exports = { callLLM, scanGeneratedCode, callUpstream, audit };

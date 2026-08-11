'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { GENERATION_SYSTEM, SECURITY_REVIEW_SYSTEM } = require('./prompts');

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, CLEAN: 0 };

const VERDICT_RE = /\bVERDICT\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW|CLEAN)\b/i;
const FINDING_RE = /^\s*[-*]\s*(CRITICAL|HIGH|MEDIUM|LOW)\b\s*:\s*(.+)$/i;

function extractJsBlock(content) {
  const m = content.match(/```(?:js|javascript)?\s*([\s\S]*?)```/i);
  if (m) return m[1].trim();
  const s = content.replace(/```/g, '').trim();
  return s;
}

function parseVerdict(text) {
  const findings = [];
  const vmatch = text.match(VERDICT_RE);
  let declared = vmatch ? vmatch[1].toUpperCase() : null;
  for (const line of String(text).split('\n')) {
    const fm = line.match(FINDING_RE);
    if (fm) findings.push({ severity: fm[1].toUpperCase(), text: fm[2].trim() });
  }
  let overall = declared;
  if (findings.length) {
    for (const f of findings) {
      if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[overall]) overall = f.severity;
    }
  }
  return { declared, findings, overall: overall || 'CLEAN' };
}

const REVIEW_MARKERS = [
  /\bVERDICT\s*:\s*CLEAN\b/i,
  /\bVERDICT\s*:\s*APPROVED\b/i,
  /\bsecurity\s+review\s+not\s+needed\b/i,
  /\breview\s+not\s+required\b/i,
  /\bdon'?t\s+(?:check|review|scan)\s+this\b/i,
  /\bуже\s+проверен[оаы]?\b/i,
  /\bодобрен[оаы]?\b/i,
];

function detectManipulation(code) {
  const found = [];
  for (const re of REVIEW_MARKERS) if (re.test(code)) found.push(re.source);
  return found;
}

function parseFindingsText(findings) {
  return findings.map(f => `${f.severity}: ${f.text}`).join(' | ');
}

function syntaxCheck(code, filePath) {
  fs.writeFileSync(filePath, code, 'utf8');
  try {
    execFileSync(process.execPath, ['--check', filePath], { stdio: 'pipe', timeout: 20000 });
    return { ok: true, error: null };
  } catch (e) {
    const err = String(e.stderr || e.message || e).slice(0, 600);
    return { ok: false, error: err };
  } finally {
    fs.unlinkSync(filePath);
  }
}

async function runTask(task, { gateway, workDir, maxAttempts = 4 }) {
  const log = {
    task: task.id,
    title: task.title,
    prompt: task.prompt,
    attempts: [],
  };

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const a = { attempt, gatewayEvents: [], feedback: null, outcome: null };

    const gen = await gateway.callLLM({ system: GENERATION_SYSTEM, user: task.prompt, purpose: 'generate', maxTokens: 1200 });
    a.gatewayEvents.push(...(gen.events || []));
    if (!gen.ok) {
      a.outcome = 'retry_gateway_blocked';
      a.feedback = `Генерация заблокирована гейтом: ${gen.blocked}${gen.types ? ' (' + gen.types.join(',') + ')' : ''}${gen.reasons ? ' — ' + gen.reasons.join(', ') : ''}`;
      a.gatewayBlocked = gen.blocked;
      log.attempts.push(a);
      break;
    }

    const code = extractJsBlock(gen.content);
    a.code = code;
    if (!code || code.length < 5) {
      a.outcome = 'retry_empty_code';
      a.feedback = 'Модель не вернула код. Повтори попытку.';
      log.attempts.push(a);
      continue;
    }

    const filePath = path.join(workDir, `${task.id}.js`);
    const test = syntaxCheck(code, path.join(workDir, `.${task.id}.tmp.js`));
    a.test = test;
    if (!test.ok) {
      a.outcome = 'retry_tests_failed';
      a.feedback = `Код не проходит проверку синтаксиса: ${test.error}`;
      log.attempts.push(a);
      continue;
    }

    const manip = detectManipulation(code);
    if (manip.length) {
      a.outcome = 'retry_manipulation';
      a.feedback = `В коде найдены маркеры попытки манипуляции ревьюером: ${manip.join(', ')}. Убери их.`;
      a.manipulation = manip;
      log.attempts.push(a);
      continue;
    }

    const review = await gateway.callLLM({ system: SECURITY_REVIEW_SYSTEM, user: `Проверь этот код:\n\n` + code, purpose: 'review', maxTokens: 800, temperature: 0 });
    a.gatewayEvents.push(...(review.events || []));
    if (!review.ok) {
      a.outcome = 'retry_gateway_blocked';
      a.feedback = `Отправка кода на ревью заблокирована гейтом: ${review.blocked}`;
      a.gatewayBlocked = review.blocked;
      log.attempts.push(a);
      break;
    }

    const verdict = parseVerdict(review.content);
    a.verdict = verdict;
    a.reviewRaw = review.content.slice(0, 600);

    const gateDecision = gate(verdict.overall);
    a.gate = gateDecision;

    if (gateDecision.retry) {
      a.outcome = 'retry_verdict';
      a.feedback = `Security review: ${verdict.overall}. Исправь: ${parseFindingsText(verdict.findings) || verdict.overall}`;
      log.attempts.push(a);
      continue;
    }

    a.outcome = 'committed';
    fs.writeFileSync(filePath, code, 'utf8');
    a.committedFile = filePath;
    log.attempts.push(a);
    log.final = { outcome: a.outcome, feedback: a.feedback, verdict: a.verdict, gate: a.gate };
    return log;
  }

  const last = log.attempts[log.attempts.length - 1];
  log.final = last ? { outcome: last.outcome, feedback: last.feedback, verdict: last.verdict, gate: last.gate } : { outcome: 'max_attempts' };
  return log;
}

function gate(severity) {
  if (severity === 'CRITICAL' || severity === 'HIGH') return { retry: true, commit: false, warning: false };
  if (severity === 'MEDIUM' || severity === 'LOW') return { retry: false, commit: true, warning: true };
  return { retry: false, commit: true, warning: false };
}

module.exports = { runTask, parseVerdict, extractJsBlock, detectManipulation, gate, syntaxCheck, SEVERITY_ORDER };

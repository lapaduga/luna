'use strict';

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const gateway = require('./gateway');
const { runTask } = require('./loop');
const tasks = require('./tasks');

const ROOT = __dirname;
const WORK_DIR = path.join(ROOT, 'generated');
const REPORT = path.join(ROOT, '..', 'reports', 'DAY14_SECURITY_STEP.md');

function renderTaskLog(log) {
  const L = [];
  L.push(`### ${log.task} — «${log.title}»`);
  L.push(`Задача: ${log.prompt}`);
  for (const a of log.attempts) {
    L.push(`\n**Попытка ${a.attempt}**`);
    const ev = a.gatewayEvents || [];
    const evStrs = ev.map(e => {
      if (e.gate === 'input_secret') return `gateway INPUT: блок секрета (${e.types.join(',')})`;
      if (e.gate === 'input_injection') return `gateway INPUT: блок инъекции (${e.reasons.join(',')})`;
      if (e.gate === 'input_risk') return `gateway INPUT: риск ${e.risk}`;
      if (e.gate === 'output_guard' && e.action === 'block') return `gateway OUTPUT: блок (${e.kinds.join(',')})`;
      if (e.gate === 'output_guard') return `gateway OUTPUT: warning (${e.kinds.join(',')})`;
      return `gateway: ${e.gate} ${e.action}`;
    });
    if (evStrs.length) L.push(`- gateway events: ${evStrs.join('; ')}`);
    if (a.manipulation) L.push(`- манипуляция ревьюером: ${a.manipulation.join(', ')}`);
    if (a.test && !a.test.ok) L.push(`- тест (синтаксис): FAILED — ${a.test.error.replace(/\n/g, ' ').slice(0, 200)}`);
    else if (a.test) L.push(`- тест (синтаксис): ok`);
    if (a.verdict) {
      L.push(`- verdict: ${a.verdict.overall} (declared=${a.verdict.declared}, findings=${a.verdict.findings.length})`);
      if (a.verdict.findings.length) L.push(`  - findings: ${a.verdict.findings.map(f => f.severity + ': ' + f.text).join(' | ')}`);
    }
    if (a.feedback) L.push(`- feedback: ${a.feedback}`);
    if (a.outcome) L.push(`- outcome: ${a.outcome}`);
  }
  L.push(`\n**Итог: ${log.final ? log.final.outcome : '—'}**\n`);
  return L.join('\n');
}

async function main() {
  fs.mkdirSync(WORK_DIR, { recursive: true });
  const parts = [
    '# ДЕНЬ 14. Execution loop с security-степом и LLM Gateway\n',
    'Архитектура: генерация (LLM через gateway) → синтаксис-тест → security review (второй LLM-вызов через gateway) → гейт (CRITICAL/HIGH → ретрай; MEDIUM/LOW → warning; CLEAN → коммит).',
    'Все вызовы LLM (и генерация, и ревью) идут через day14/gateway.js, который прогоняет каждый запрос/ответ через guards.js (input-секреты, инъекции, output-скан).',
    'Генерированный код из каждой попытки ретрая НЕ коммитится: файл в day14/generated/ записывается только при итоговом `committed`.\n',
    'Модель генерации: ' + (process.env.DEEPSEEK_MODEL || 'deepseek-v4-pro') + '; модель ревью: ' + (process.env.DEEPSEEK_GUARD_MODEL || 'deepseek-v4-flash') + '\n',
  ];

  const allLogs = [];
  for (const task of tasks) {
    process.stdout.write(`\n=== ${task.id}: ${task.title} ===\n`);
    const log = await runTask(task, { gateway, workDir: WORK_DIR, maxAttempts: 4 });
    allLogs.push(log);
    parts.push(renderTaskLog(log));
    const last = log.attempts[log.attempts.length - 1];
    process.stdout.write(`  outcome: ${log.final.outcome}\n`);
    if (last && last.verdict) process.stdout.write(`  verdict: ${last.verdict.overall} (findings=${last.verdict.findings.length})\n`);
  }

  parts.push(renderSummary(allLogs));

  const gatewayLogPath = path.join(ROOT, 'gateway_audit.jsonl');
  if (fs.existsSync(gatewayLogPath)) {
    const events = fs.readFileSync(gatewayLogPath, 'utf8').trim().split('\n').filter(Boolean);
    parts.push('\n## Аудит gateway (gateway_audit.jsonl)\n');
    parts.push('```jsonl');
    parts.push(events.slice(-40).join('\n'));
    parts.push('```');
  }

  fs.writeFileSync(REPORT, parts.join('\n\n'), 'utf8');
  process.stdout.write('\nSAVED ' + REPORT + '\n');
}

function renderSummary(logs) {
  const L = [];
  L.push('\n## Сводка: что поймал security review, что поймал gateway, что пропустили оба\n');
  L.push('| Задача | Итог | Попыток | Security review (главное) | Gateway (события) | Пропущено обоими |');
  L.push('|---|---|---|---|---|---|');
  for (const log of logs) {
    const sev = [];
    const gw = [];
    let missed = '—';
    for (const a of log.attempts) {
      for (const ev of (a.gatewayEvents || [])) {
        if (ev.gate === 'input_secret') gw.push(`блок входного секрета`);
        else if (ev.gate === 'input_injection') gw.push(`блок инъекции`);
        else if (ev.gate === 'output_guard' && ev.action === 'block') gw.push(`блок выхода (${ev.kinds.join(',')})`);
        else if (ev.gate === 'output_guard') gw.push(`предупреждение выхода (${(ev.kinds || []).join(',')})`);
        else if (ev.gate === 'input_secret_soft') gw.push(`soft-секрет на входе`);
        else if (ev.gate === 'input_risk') gw.push(`риск входа (${ev.risk})`);
      }
      if (a.verdict && a.verdict.overall && a.verdict.overall !== 'CLEAN') sev.push(a.verdict.overall);
    }
    const uniqueSev = [...new Set(sev)].join(', ') || 'CLEAN';
    const uniqueGw = [...new Set(gw)].join('; ') || '—';
    const firstFindings = (log.attempts.find(a => a.verdict && a.verdict.findings && a.verdict.findings.length) || {}).verdict;
    const topFinding = firstFindings ? firstFindings.findings.slice(0, 2).map(f => f.severity + ': ' + f.text.slice(0, 70)).join('<br>') : '—';
    L.push(`| ${log.task} | ${log.final.outcome} | ${log.attempts.length} | ${topFinding} | ${uniqueGw} | ${missed} |`);
  }
  L.push('');
  return L.join('\n');
}

main().catch((e) => { console.error(e); process.exit(1); });

'use strict';

/* ===========================================================================
   Детерминированные гейты LLM-шлюза «Луны» (Дни 12–15).
   Чистые функции без обращения к env — конфиг передаёт вызывающий код.
   Слои: sanitize → детект секретов → маска → эвристики инъекций → output-scan.
   =========================================================================== */

const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF]/g;
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const WHITESPACE_RE = /\s+/g;

/** Убираем управляющие и zero-width символы, режем по длине. Строки сообщений сохраняем как есть. */
function sanitizeText(text, maxLen = 4000) {
  if (typeof text !== 'string') return '';
  return text.replace(ZERO_WIDTH_RE, '').replace(CONTROL_RE, '').slice(0, maxLen);
}

/** Для коротких полей (данные цикла): ещё и схлопываем пробелы. */
function sanitizeField(text, maxLen = 120) {
  if (typeof text !== 'string') return '';
  return sanitizeText(text, maxLen).replace(WHITESPACE_RE, ' ').trim();
}

/* ---------------------------------------------------------------------------
   Секреты
   --------------------------------------------------------------------------- */

/** Проверка Луна-алгоритма для номеров карт. */
function luhnValid(digitsStr) {
  const digits = digitsStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// hard = блокировать по умолчанию; soft = маскировать.
const SECRET_PATTERNS = [
  { type: 'AWS_ACCESS_KEY', hard: true, re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'PRIVATE_KEY', hard: true, re: /-----BEGIN[^-]+PRIVATE KEY-----/g },
  { type: 'GITHUB_TOKEN', hard: true, re: /\b(?:ghp_|gho_|ghu_|github_pat_)[A-Za-z0-9_]{20,}\b/g },
  { type: 'GOOGLE_API_KEY', hard: true, re: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
  { type: 'STRIPE_KEY', hard: true, re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g },
  { type: 'SLACK_TOKEN', hard: true, re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { type: 'API_KEY', hard: true, re: /\bsk-[A-Za-z0-9_-]{12,}\b/g },
  { type: 'JWT', hard: true, re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { type: 'CREDIT_CARD', hard: true, re: /\b(?:\d[ -]?){13,19}\b/g, validate: luhnValid },
  { type: 'EMAIL', hard: false, re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: 'PHONE', hard: false, re: /(?:\+?\d[\s\-()]*){10,15}\d/g },
];

// «Фрагменты» ключей: ловим даже разбитые секреты вида "мой ключ: sk-" + "proj-abc".
const FRAGMENT_PATTERNS = [
  // Без хвостового \b: «sk- » с пробелом — тоже фрагмент ключа.
  { type: 'KEY_FRAGMENT', hard: true, re: /\b(?:sk-|ghp_|gho_|ghu_|github_pat_|AKIA|ASIA|BEGIN [A-Z ]*PRIVATE KEY)/g },
  { type: 'TOKEN_ASSIGN', hard: false, re: /\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S{6,}\b/gi },
];

function looksLikeBase64(blob) {
  if (!/[a-z]/.test(blob) && !/[A-Z]/.test(blob)) return false;
  const letters = (blob.match(/[a-zA-Z0-9]/g) || []).length;
  return letters >= 24 && letters / blob.length > 0.9;
}

// ВАЖНО: scanBase64 создаёт свой (локальный) regex. Общий глобальный regex +
// рекурсия сбрасывали бы lastIndex и зацикливались. Вложенный скан — без base64,
// чтобы рекурсия была ограничена глубиной 1.
function scanBase64(text) {
  const found = [];
  const re = /\b([A-Za-z0-9+/]{24,}={0,2})\b/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const blob = m[1];
    if (!looksLikeBase64(blob)) continue;
    let decoded = '';
    try { decoded = Buffer.from(blob, 'base64').toString('utf8'); } catch { continue; }
    if (!/[\x20-\x7E\u0400-\u04FF]{4,}/.test(decoded)) continue;
    const inner = detectCore(decoded, { base64: false });
    if (inner.some(s => s.hard)) found.push({ type: 'BASE64_SECRET', hard: true, sample: 'base64-блоб' });
    else found.push({ type: 'BASE64', hard: false, sample: 'base64-блоб' });
  }
  return found;
}

/** Ядро сканера. options.base64=false отключает вложенный base64-скан. */
function detectCore(text, options) {
  if (typeof text !== 'string') return [];
  const base64 = !options || options.base64 !== false;
  const out = [];
  const seen = new Set();
  const push = (s) => {
    const key = s.type + ':' + (s.sample || '');
    if (seen.has(key)) return;
    seen.add(key);
    out.push(s);
  };
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.re.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      if (p.validate && !p.validate(m[0])) continue;
      push({ type: p.type, hard: p.hard, sample: `[${p.type}]` });
    }
  }
  for (const p of FRAGMENT_PATTERNS) {
    const re = new RegExp(p.re.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      push({ type: p.type, hard: p.hard, sample: `[${p.type}]` });
    }
  }
  if (base64) for (const s of scanBase64(text)) push(s);
  return out;
}

/** Все секреты в тексте: [{ type, hard, sample }]. sample уже обезличен. */
function detectSecrets(text) {
  return detectCore(text);
}

const MASK_LABEL = { API_KEY: 'REDACTED_API_KEY', CREDIT_CARD: 'REDACTED_CARD', EMAIL: 'REDACTED_EMAIL', PHONE: 'REDACTED_PHONE' };
function maskLabel(type) { return MASK_LABEL[type] || `REDACTED_${type}`; }

/** Заменяем найденные секреты на [REDACTED_*]. Порядок: сначала крупные (ключи/карты), потом soft. */
function maskSecretTypes(text) {
  if (typeof text !== 'string') return text;
  const order = [
    ...SECRET_PATTERNS.filter(p => p.hard),
    ...FRAGMENT_PATTERNS.filter(p => p.hard),
    ...SECRET_PATTERNS.filter(p => !p.hard),
    ...FRAGMENT_PATTERNS.filter(p => !p.hard),
  ];
  let out = text;
  for (const p of order) {
    const re = new RegExp(p.re.source, 'g');
    out = out.replace(re, (match) => {
      if (p.validate && !p.validate(match)) return match;
      return `[${maskLabel(p.type)}]`;
    });
  }
  return out;
}

/* ---------------------------------------------------------------------------
   Инъекции (эвристики). Возврат: { risk: 'none'|'low'|'medium'|'high', reasons: [] }
   --------------------------------------------------------------------------- */

const INJECTION_RULES = [
  // instruction override — англ.
  { risk: 'high', name: 'instruction_override', re: /(?:ignore|disregard|forget).{0,40}(?:all|previous|prior|above|earlier|your)?\s*(?:instructions|prompts?|rules|system\s+prompt)/i },
  // instruction override — рус.
  { risk: 'high', name: 'instruction_override_ru', re: /(?:забудь|проигнорируй|игнорируй|не\s+выполняй|не\s+следуй|отмени).{0,30}(?:все|свои|предыдущие|прежние|системные)?\s*(?:инструкции|инструкций|правила|правил|промпт)/i },
  // jailbreak / role-play
  { risk: 'high', name: 'jailbreak', re: /\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak/i },
  { risk: 'high', name: 'role_override_ru', re: /(?:ты\s+теперь|отныне\s+ты|теперь\s+ты|действуй\s+как).{0,40}(?:делаешь\s+вс[её]|можешь\s+вс[её]|без\s+ограничени|вс[её]\s+что\s+угодно|не\s+подчиня)/i },
  { risk: 'high', name: 'refusal_bypass', re: /(?:никогда\s+не\s+отказывай|ты\s+обязан\s+выполнять|не\s+имей\s+ограничений|ignore\s+refusals)/i },
  // system prompt extraction — англ.
  { risk: 'high', name: 'extraction_en', re: /(?:repeat|show|print|reveal|display|dump|paste|copy).{0,40}(?:system\s+prompt|system\s+message|initial\s+instructions?|all\s+instructions?|everything\s+above|your\s+prompt)/i },
  // system prompt extraction — рус.
  { risk: 'high', name: 'extraction_ru', re: /(?:повтори|покажи|напиши|выведи|раскрой|расскажи|скажи|выдай|продемонстрируй).{0,40}(?:системный\s+промпт|системное\s+сообщение|свои\s+инструкции|все\s+инструкции|инструкции\s+целиком|весь\s+промпт|вс[её]\s*,?\s+что\s+(?:написано|сверху|выше)|текст\s+выше|первое\s+сообщение)/i },
  // скрытые команды / формат
  { risk: 'medium', name: 'from_now_on', re: /from\s+now\s+on/i },
  { risk: 'medium', name: 'always_start', re: /always\s+(?:start|begin)\s+your\s+(?:answer|response|reply)\s+with/i },
  { risk: 'medium', name: 'always_start_ru', re: /(?:всегда\s+начинай|начинай\s+свой\s+ответ|обязательно\s+добавь|в\s+каждом\s+ответе)/i },
  { risk: 'medium', name: 'delimiter_confusion', re: /(?:ignore|забудь).{0,20}(?:<|\[)?(?:system|user_input)/i },
];

/** Классификация риска инъекции в тексте. */
function classifyRisk(text) {
  if (typeof text !== 'string' || !text.trim()) return { risk: 'none', reasons: [] };
  const reasons = [];
  let risk = 'none';
  for (const rule of INJECTION_RULES) {
    if (rule.re.test(text)) {
      reasons.push(rule.name);
      if (rule.risk === 'high') risk = 'high';
      else if (risk !== 'high' && rule.risk === 'medium' && risk === 'none') risk = 'medium';
    }
  }
  return { risk, reasons };
}

/* ---------------------------------------------------------------------------
   Output guard
   --------------------------------------------------------------------------- */

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const SUSPICIOUS_HOST_RE = /(webhook\.site|requestbin|pipedream\.com|ngrok|burpcollaborator|trycloudflare|discord\.com\/api|api\.telegram\.org\/bot|oast\w*\.|interact\.sh|dnslog\w*\.|hookbin|beeceptor)/i;
const IP_HOST_RE = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i;

function detectSuspiciousUrls(text) {
  const found = [];
  let m;
  while ((m = URL_RE.exec(text)) !== null) {
    const u = m[0];
    const lower = u.toLowerCase();
    if (lower.startsWith('http://') || IP_HOST_RE.test(lower) || SUSPICIOUS_HOST_RE.test(lower)) {
      found.push(u);
    }
  }
  return found;
}

const COMMAND_RULES = [
  /curl\b[^\n]*\|\s*(?:sh|bash)\b/i,
  /wget\b[^\n]*\|\s*(?:sh|bash)\b/i,
  /\b(?:eval|exec)\s*\(/i,
  /\bchild_process\b/i,
  /\brequire\(['"]fs['"]\)/i,
  /\bos\.system\b/i,
  /base64\s*-\s*d\b[^\n]*\|\s*(?:sh|bash)\b/i,
  /\/dev\/tcp\//,
  /\b(?:sh|bash|powershell|cmd)\s+-[ec]\s+["']/i,
  /\brm\s+-rf\s+\/[^ ]*\b/i,
];

function detectSuspiciousCommands(text) {
  const found = [];
  for (const re of COMMAND_RULES) if (re.test(text)) found.push(re.source);
  return found;
}

/**
 * Полный скан выхода модели.
 * @param {string} text - сгенерированный текст
 * @param {string[]} canaries - сигнатуры системного промпта (для детекта утечки)
 * @returns {{severity:'ok'|'warn'|'block', problems:Array}}
 */
function scanOutput(text, canaries = []) {
  const problems = [];
  if (typeof text !== 'string' || !text) return { severity: 'ok', problems };

  const secrets = detectSecrets(text);
  const hard = secrets.filter(s => s.hard);
  const soft = secrets.filter(s => !s.hard);
  if (hard.length) problems.push({ kind: 'secret', severity: 'block', detail: hard.map(s => s.type).join(',') });
  if (soft.length) problems.push({ kind: 'secret_soft', severity: 'warn', detail: soft.map(s => s.type).join(',') });

  const leak = canaries.filter(c => c && c.length > 3 && text.includes(c));
  if (leak.length) problems.push({ kind: 'system_prompt_leak', severity: 'block', detail: leak.join(' | ') });

  const urls = detectSuspiciousUrls(text);
  if (urls.length) problems.push({ kind: 'suspicious_url', severity: 'block', detail: urls.join(' | ') });

  const cmds = detectSuspiciousCommands(text);
  if (cmds.length) problems.push({ kind: 'suspicious_command', severity: 'block', detail: cmds.join(' | ') });

  const worst = problems.some(p => p.severity === 'block') ? 'block' : (problems.length ? 'warn' : 'ok');
  return { severity: worst, problems };
}

/* ---------------------------------------------------------------------------
   Утилиты
   --------------------------------------------------------------------------- */

function estimateTokens(text) {
  return Math.ceil(String(text || '').length / 4);
}

/** Безопасный preview для логов: маскируем секреты и режем. */
function redactPreview(text, maxLen = 140) {
  const masked = maskSecretTypes(String(text || ''));
  return masked.replace(/\s+/g, ' ').slice(0, maxLen);
}

module.exports = {
  sanitizeText,
  sanitizeField,
  detectSecrets,
  maskSecretTypes,
  classifyRisk,
  scanOutput,
  scanBase64,
  estimateTokens,
  redactPreview,
  luhnValid,
};

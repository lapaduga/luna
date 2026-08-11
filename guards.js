'use strict';

/* ===========================================================================
   Детерминированные гейты LLM-шлюза «Луны» (Дни 12–15).
   Чистые функции без обращения к env — конфиг передаёт вызывающий код.
   Слои: sanitize → детект секретов → маска → эвристики инъекций → output-scan.
   =========================================================================== */

// Невидимые / формат-символы: zero-width space, non-joiner/joiner, word-joiner,
// BOM, bidi-управляющие, arabic letter mark И soft hyphen (U+00AD).
// Soft hyphen не входил в старый диапазон — через него обходили детект секретов.
const INVISIBLE_RE = /[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
const INVISIBLE_CODES = new Set([
  0x00AD, 0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
  0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF,
]);
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const WHITESPACE_RE = /\s+/g;

/** Убираем управляющие, zero-width, soft hyphen и bidi-символы; режем по длине. */
function sanitizeText(text, maxLen = 4000) {
  if (typeof text !== 'string') return '';
  return text.replace(INVISIBLE_RE, '').replace(CONTROL_RE, '').slice(0, maxLen);
}

// Визуальные homoglyphs: кириллица, неотличимая от латиницы (только 1:1 буквы).
// Не включаем Б/Г/Д/З/Л — они не похожи на латинские буквы.
const CYRILLIC_TO_LATIN = new Map([
  ['А', 'A'], ['В', 'B'], ['Е', 'E'], ['К', 'K'], ['М', 'M'], ['Н', 'H'], ['О', 'O'],
  ['Р', 'P'], ['С', 'C'], ['Т', 'T'], ['У', 'Y'], ['Х', 'X'], ['І', 'I'], ['Ѕ', 'S'], ['Ј', 'J'],
  ['а', 'a'], ['в', 'b'], ['е', 'e'], ['к', 'k'], ['м', 'm'], ['н', 'h'], ['о', 'o'],
  ['р', 'p'], ['с', 'c'], ['т', 't'], ['у', 'y'], ['х', 'x'], ['і', 'i'], ['ѕ', 's'], ['ј', 'j'],
]);

/**
 * Нормализация для детекции: вырезает невидимые символы (soft hyphen, zero-width,
 * bidi), сводит full-width (FF01–FF5E) к ASCII и кириллические homoglyphs к латинице.
 * Возвращает { norm, map }, где map[normIndex] = индекс символа в исходной строке —
 * нужно, чтобы позиции найденных секретов можно было вернуть в оригинал.
 */
function normalizeForDetection(text) {
  if (typeof text !== 'string') return { norm: '', map: [] };
  let norm = '';
  const map = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (INVISIBLE_CODES.has(code)) continue;
    let ch = text[i];
    if (code >= 0xFF01 && code <= 0xFF5E) ch = String.fromCharCode(code - 0xFEE0);
    else ch = CYRILLIC_TO_LATIN.get(ch) || ch;
    map.push(i);
    norm += ch;
  }
  return { norm, map };
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

const MAX_BASE64_DEPTH = 3;

/**
 * Ищет base64-блоб и декодирует его рекурсивно (глубина до MAX_BASE64_DEPTH),
 * чтобы поймать и одинарное, и двойное (base64x2) кодирование секрета.
 * Возвращает массив { s, e, hard } — позиции блоба в text и факт hard-секрета внутри.
 */
function base64Blobs(text, depth) {
  const out = [];
  if (typeof text !== 'string' || depth > MAX_BASE64_DEPTH) return out;
  const re = /\b([A-Za-z0-9+/]{24,}={0,2})\b/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const blob = m[1];
    if (!looksLikeBase64(blob)) continue;
    let decoded = '';
    try { decoded = Buffer.from(blob, 'base64').toString('utf8'); } catch { continue; }
    if (!/[\x20-\x7E\u0400-\u04FF]{4,}/.test(decoded)) continue;
    const inner = detectCore(decoded, { base64: true, norm: true, depth: depth + 1 });
    if (inner.length) out.push({ s: m.index, e: m.index + m[0].length, hard: inner.some(s => s.hard) });
  }
  return out;
}

/** Массив { type, hard, sample } для всех base64-блобов в text. */
function scanBase64(text, depth) {
  return base64Blobs(text, depth == null ? 1 : depth).map(b =>
    b.hard
      ? { type: 'BASE64_SECRET', hard: true, sample: 'base64-блоб' }
      : { type: 'BASE64', hard: false, sample: 'base64-блоб' }
  );
}

/**
 * Ядро сканера. options:
 *  - norm=false — не нормализовать (текст уже нормализован);
 *  - base64=false — отключить вложенный base64-скан;
 *  - depth — текущая глубина рекурсии base64.
 */
function detectCore(text, options) {
  if (typeof text !== 'string') return [];
  const opts = options || {};
  const base64 = opts.base64 !== false;
  const target = (opts.norm === false) ? text : normalizeForDetection(text).norm;
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
    while ((m = re.exec(target)) !== null) {
      if (p.validate && !p.validate(m[0])) continue;
      push({ type: p.type, hard: p.hard, sample: `[${p.type}]` });
    }
  }
  for (const p of FRAGMENT_PATTERNS) {
    const re = new RegExp(p.re.source, 'g');
    let m;
    while ((m = re.exec(target)) !== null) {
      push({ type: p.type, hard: p.hard, sample: `[${p.type}]` });
    }
  }
  if (base64) {
    for (const b of base64Blobs(target, (opts.depth || 0) + 1)) {
      push(b.hard
        ? { type: 'BASE64_SECRET', hard: true, sample: 'base64-блоб' }
        : { type: 'BASE64', hard: false, sample: 'base64-блоб' });
    }
  }
  return out;
}

/** Все секреты в тексте (с учётом soft hyphen, fullwidth, homoglyph, base64xN). */
function detectSecrets(text) {
  return detectCore(text);
}

const MASK_LABEL = { API_KEY: 'REDACTED_API_KEY', CREDIT_CARD: 'REDACTED_CARD', EMAIL: 'REDACTED_EMAIL', PHONE: 'REDACTED_PHONE', BASE64: 'REDACTED_BASE64' };
function maskLabel(type) { return MASK_LABEL[type] || `REDACTED_${type}`; }

const MASK_SOURCES = [...SECRET_PATTERNS, ...FRAGMENT_PATTERNS];

/**
 * Маскируем секреты с учётом обфускации (soft hyphen, fullwidth, homoglyph,
 * base64). Детекция идёт по нормализованному тексту, замена — по карте позиций
 * в оригинале. Перекрывающиеся участки склеиваются, лейбл берётся у «старшего»
 * паттерна (hard-ключи идут раньше soft).
 */
function maskSecretTypes(text) {
  if (typeof text !== 'string') return text;
  const { norm, map } = normalizeForDetection(text);
  const spans = [];
  for (let pi = 0; pi < MASK_SOURCES.length; pi++) {
    const p = MASK_SOURCES[pi];
    const re = new RegExp(p.re.source, 'g');
    let m;
    while ((m = re.exec(norm)) !== null) {
      if (p.validate && !p.validate(m[0])) continue;
      spans.push({ s: m.index, e: m.index + m[0].length, label: maskLabel(p.type), prio: pi });
    }
  }
  for (const b of base64Blobs(norm, 1)) {
    spans.push({ s: b.s, e: b.e, label: b.hard ? 'REDACTED_BASE64_SECRET' : maskLabel('BASE64'), prio: MASK_SOURCES.length });
  }
  if (!spans.length) return text;

  spans.sort((a, b) => a.s - b.s || a.prio - b.prio);
  const merged = [];
  for (const sp of spans) {
    const last = merged[merged.length - 1];
    if (last && sp.s <= last.e) last.e = Math.max(last.e, sp.e);
    else merged.push(sp);
  }

  let out = text;
  for (let i = merged.length - 1; i >= 0; i--) {
    const sp = merged[i];
    const os = map[sp.s];
    const oe = map[sp.e - 1] + 1;
    if (os == null || oe <= os) continue;
    out = out.slice(0, os) + `[${sp.label}]` + out.slice(oe);
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
  // Перефразы, которые в раунде 1 обходили эвристики (партнёрская атака).
  // ВАЖНО: \w и \b в JS — только ASCII, поэтому после кириллицы используем \p{L}.
  { risk: 'high', name: 'extraction_quote', re: /(?:процитируй|процитируйте|цитировать|приведи\s+цитат\p{L}*|цитат\p{L}*).{0,80}(?:системн\p{L}*\s+(?:промпт|сообщение|инструкц\p{L}+)|инструкц\p{L}+|текст)/iu },
  { risk: 'high', name: 'extraction_debug', re: /(?:для\s+(?:дебага|отладки)|debug|дебаг).{0,80}(?:системн\p{L}*|инструкц\p{L}+|промпт|правил\p{L}*)|(?:точный\s+текст|одним\s+блоком|целиком).{0,60}(?:системн\p{L}*|инструкц\p{L}+|промпт)/iu },
  { risk: 'high', name: 'instruction_supersede', re: /(?:с\s+этого\s+момента|отныне|дальше|теперь)[^.\n]{0,50}?(?:предыдущ\p{L}+|прежн\p{L}+|стары\p{L}*)[^.\n]{0,60}?(?:больше\s+не|не\s+(?:действ\p{L}+|работа\p{L}+|учитывай|соблюдай|нужно)|аннулир\p{L}+|отмен\p{L}+|не\s+актуальн\p{L}*)/iu },
];

// Сигнальные слова для «спорных» текстов: эвристики дали none, но текст стоит
// показать LLM-классификатору (GUARD_LLM), чтобы он решил сам.
const REVIEW_RE = /(?:системн\p{L}*|промпт|инструкц\p{L}+|правил\p{L}*|system\s+prompt|instructions?|rules|повтор\p{L}+|дословн\p{L}+|цитат\p{L}+|процитируй|текст\s+выше|написан\p{L}+\s+выше|дебаг|debug|отладк\p{L}+|с\s+этого\s+момента|отныне)/iu;

/** Классификация риска инъекции в тексте. review=true — эвристики «none», но стоит LLM-перепроверка. */
function classifyRisk(text) {
  if (typeof text !== 'string' || !text.trim()) return { risk: 'none', reasons: [], review: false };
  const reasons = [];
  let risk = 'none';
  for (const rule of INJECTION_RULES) {
    if (rule.re.test(text)) {
      reasons.push(rule.name);
      if (rule.risk === 'high') risk = 'high';
      else if (risk !== 'high' && rule.risk === 'medium' && risk === 'none') risk = 'medium';
    }
  }
  const review = risk === 'none' && REVIEW_RE.test(text);
  return { risk, reasons, review };
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

/* ---------------------------------------------------------------------------
   Output guard: позиции проблем (для инкрементального стриминга)
   --------------------------------------------------------------------------- */

/**
 * Находит индексы всех проблем в тексте. Нужно для гибридного стрима:
 * сервер доставляет контент до минимального block-индекса, потом обрывает.
 * @returns {{ block: Array<{index:number,kind:string,len:number}>, warn: Array<{index:number,kind:string,len:number}> }}
 */
function findProblemIndices(text, canaries = []) {
  const block = [];
  const warn = [];
  if (typeof text !== 'string' || !text) return { block, warn };

  // Детекция секретов идёт по нормализованному тексту (soft hyphen, fullwidth,
  // homoglyph), а индексы возвращаются в координатах ОРИГИНАЛА через map.
  const { norm, map } = normalizeForDetection(text);
  const at = (normIdx) => (map[normIdx] != null ? map[normIdx] : normIdx);

  for (const p of [...SECRET_PATTERNS, ...FRAGMENT_PATTERNS]) {
    const re = new RegExp(p.re.source, 'g');
    let m;
    while ((m = re.exec(norm)) !== null) {
      if (p.validate && !p.validate(m[0])) continue;
      const s = at(m.index);
      const e = at(m.index + m[0].length - 1) + 1;
      (p.hard ? block : warn).push({ index: s, kind: p.type, len: e - s });
    }
  }

  for (const b of base64Blobs(norm, 1)) {
    const s = at(b.s);
    const e = at(b.e - 1) + 1;
    (b.hard ? block : warn).push({ index: s, kind: b.hard ? 'BASE64_SECRET' : 'BASE64', len: e - s });
  }

  for (const c of canaries) {
    if (!c || c.length <= 3) continue;
    let i = 0;
    while ((i = text.indexOf(c, i)) !== -1) {
      block.push({ index: i, kind: 'system_prompt_leak', len: c.length });
      i += c.length;
    }
  }

  const ure = new RegExp(URL_RE.source, 'g');
  let um;
  while ((um = ure.exec(text)) !== null) {
    const u = um[0];
    const lower = u.toLowerCase();
    if (lower.startsWith('http://') || IP_HOST_RE.test(lower) || SUSPICIOUS_HOST_RE.test(lower)) {
      block.push({ index: um.index, kind: 'suspicious_url', len: um[0].length });
    }
  }

  for (const rule of COMMAND_RULES) {
    const re = new RegExp(rule.source, 'g');
    let cm;
    while ((cm = re.exec(text)) !== null) {
      block.push({ index: cm.index, kind: 'suspicious_command', len: cm[0].length });
    }
  }

  return { block, warn };
}

/** Только блокирующие проблемы: severity 'block' | 'warn' | 'ok'. */
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
  findProblemIndices,
  scanBase64,
  base64Blobs,
  normalizeForDetection,
  estimateTokens,
  redactPreview,
  luhnValid,
};

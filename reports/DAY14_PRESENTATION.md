# ДЕНЬ 14. Execution loop с security step + LLM Gateway (демо для преподавателя)

**Суть:** цикл «генерация кода → тест → security review вторым LLM-вызовом → гейт → коммит/ретрай».
Все LLM-вызовы идут через LLM Gateway (guards.js): секреты, инъекции и output-скан на каждом шаге.

## Схема цикла

```
Промпт (задача)
   │ 1. Генерация кода (LLM через Gateway)
   ▼
Синтаксис-тест (node --check) ── нет → фидбек, ретрай
   │ да
   ▼
Security review (второй LLM-вызов через Gateway, промпт под Node/Express)
   │
   ▼
CRITICAL/HIGH → «исправь: …» → ретрай
MEDIUM/LOW   → warning в лог + коммит
CLEAN        → коммит (файл в generated/)
```

## Что поймали: 3 задачи (живой прогон)

| Задача | Security review поймал | Gateway поймал | Итог |
|---|---|---|---|
| save_auth_token («сохрани токен») | CRITICAL/HIGH ×3: хранение токенов в открытом виде, отсутствие авторизации, нет rate limiting | warning: soft-признак `TOKEN_ASSIGN` в коде | 4-я попытка CLEAN → коммит |
| log_all_requests («логируй все запросы») | HIGH: логирование тел/заголовков с чувствительными данными | — | ретрай → CLEAN-версия с маскировкой → коммит |
| call_external_api («запрос на API») | CLEAN с 1-й попытки (код: https, таймаут, валидация id, ключ из env) | — | коммит |

Честное примечание: в этих прогонах ни один вызов не был блокирован гейтом целиком (блок сработал бы на `sk-…`/`http://evil.com` в коде — проверено отдельно). Основную работу сделал security review; гейт — резервный эшелон.

## Файлы

- `day14/loop.js` — execution loop + гейт
- `day14/gateway.js` — LLM Gateway-клиент (все вызовы через guards.js + аудит)
- `day14/prompts.js` — промпты: генерация + security review под Node/Express
- `day14/tasks.js` — 3 задачи
- `day14/generated/*.js` — финальный чистый код
- `tests/day14_loop.test.js` — 12 юнит-тестов (парсинг вердиктов, гейт, манипуляции)

Тесты: `node --test` → 43 passed (31 guards + 12 loop).

'use strict';

/* ===========================================================================
   Чат с «Луной». Рендер сообщений строится только через createElement и
   textContent — никакой innerHTML с пользовательским или модельным текстом.
   =========================================================================== */

const LunaChat = (() => {
  const HISTORY_KEY = 'luna-chat-history';
  const MAX_HISTORY = 20;

  const els = {
    messages: null,
    input: null,
    send: null,
    cancel: null,
    chips: null,
    clear: null,
  };

  let history = [];
  let sending = false;
  let abortController = null;

  /* ---- XSS-безопасный рендер markdown в DOM ---- */

  function addInline(parent, text) {
    // **жирный**
    const boldParts = String(text).split(/\*\*([^*]+)\*\*/g);
    for (let i = 0; i < boldParts.length; i++) {
      const part = boldParts[i];
      if (part === '' || part === undefined) continue;
      if (i % 2 === 1) {
        const b = document.createElement('strong');
        b.textContent = part;
        parent.appendChild(b);
        continue;
      }
      // *курсив*
      const italicParts = part.split(/\*([^*]+)\*/g);
      for (let j = 0; j < italicParts.length; j++) {
        const ip = italicParts[j];
        if (ip === '' || ip === undefined) continue;
        if (j % 2 === 1) {
          const em = document.createElement('em');
          em.textContent = ip;
          parent.appendChild(em);
          continue;
        }
        // `код`
        const codeParts = ip.split(/`([^`]+)`/g);
        for (let k = 0; k < codeParts.length; k++) {
          const cp = codeParts[k];
          if (cp === '' || cp === undefined) continue;
          if (k % 2 === 1) {
            const c = document.createElement('code');
            c.textContent = cp;
            parent.appendChild(c);
          } else {
            parent.appendChild(document.createTextNode(cp));
          }
        }
      }
    }
  }

  function renderMarkdown(text) {
    const frag = document.createDocumentFragment();
    const blocks = String(text).split(/\n\s*\n/);

    for (const block of blocks) {
      const lines = block.split('\n').filter(l => l.trim() !== '');
      if (lines.length === 0) continue;

      const allBullets = lines.every(l => /^\s*[-*]\s+/.test(l));
      const allNumbered = lines.every(l => /^\s*\d+[.)]\s+/.test(l));

      if (allBullets || allNumbered) {
        const list = document.createElement(allBullets ? 'ul' : 'ol');
        for (const line of lines) {
          const li = document.createElement('li');
          const content = line.replace(/^\s*[-*]\s+/, '').replace(/^\s*\d+[.)]\s+/, '');
          addInline(li, content);
          list.appendChild(li);
        }
        frag.appendChild(list);
        continue;
      }

      for (const line of lines) {
        const t = line.trim();
        if (t.startsWith('## ')) {
          const h = document.createElement('h4');
          h.textContent = t.slice(3);
          frag.appendChild(h);
          continue;
        }
        if (t.startsWith('> ')) {
          const q = document.createElement('blockquote');
          addInline(q, t.slice(2));
          frag.appendChild(q);
          continue;
        }
        const p = document.createElement('p');
        addInline(p, t);
        frag.appendChild(p);
      }
    }
    return frag;
  }

  /* ---- сообщения ---- */

  /* ---- аватар Луны (наша SVG-константа) ---- */
  const AVATAR_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
    '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="currentColor"/></svg>';

  function addMessage(role, content, streaming = false) {
    const wrapper = document.createElement('div');
    wrapper.className = `msg msg--${role}`;

    if (role === 'bot') {
      const avatar = document.createElement('span');
      avatar.className = 'avatar';
      avatar.innerHTML = AVATAR_SVG;
      wrapper.appendChild(avatar);
    }

    const bubble = document.createElement('div');
    bubble.className = 'bubble';

    if (role === 'bot' && streaming) {
      bubble.dataset.streaming = '1';
    }

    if (role === 'user') {
      bubble.textContent = content;
    } else {
      bubble.appendChild(renderMarkdown(content));
    }

    wrapper.appendChild(bubble);
    els.messages.appendChild(wrapper);
    scrollDown();
    return { wrapper, bubble, setText(raw) { bubble.replaceChildren(renderMarkdown(raw)); } };
  }

  function scrollDown() {
    els.messages.scrollTop = els.messages.scrollHeight;
  }

  /* ---- история ---- */

  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          history = parsed
            .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
            .slice(-MAX_HISTORY);
        }
      }
    } catch {
      history = [];
    }
  }

  function saveHistory() {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-MAX_HISTORY)));
    } catch (e) {
      console.warn('Не удалось сохранить историю чата:', e.message);
    }
  }

  function resetHistory() {
    history = [];
    saveHistory();
    els.messages.replaceChildren();
    const welcome = addMessage('bot', 'Здравствуйте, я Луна. Я рядом, чтобы помочь разобраться с вашим циклом, поддержать в непростые дни и — если вы этого хотите — поговорить о том, что живёт глубже тела: о ритмах, душе и внутреннем свете. Как вы себя чувствуете?');
    renderSuggestionChips();
  }

  /* ---- быстрые подсказки ---- */

  const SUGGESTIONS = [
    'Как снять боль при месячных?',
    'Дай аффирмацию на сегодня',
    'Какая сейчас фаза моего цикла?',
    'Что происходит с моим телом сейчас?',
  ];

  function renderSuggestionChips() {
    const container = document.querySelector('.chips');
    if (!container) return;
    container.replaceChildren();
    const label = document.createElement('span');
    label.className = 'chips-label';
    label.textContent = 'О чём поговорить:';
    container.appendChild(label);
    for (const s of SUGGESTIONS) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip';
      btn.textContent = s;
      btn.addEventListener('click', () => {
        els.input.value = s;
        els.input.focus();
      });
      container.appendChild(btn);
    }
  }

  /* ---- отправка ---- */

  function setBusy(busy) {
    sending = busy;
    els.send.disabled = busy;
    els.input.disabled = busy;
    els.send.classList.toggle('hidden', busy);
    els.cancel.classList.toggle('hidden', !busy);
  }

  async function send() {
    const text = els.input.value.trim();
    if (!text || sending) return;

    addMessage('user', text);
    history.push({ role: 'user', content: text });
    els.input.value = '';
    setBusy(true);

    const bot = addMessage('bot', '', true);
    let raw = '';

    const body = {
      messages: history.slice(-MAX_HISTORY),
      cycleData: LunaCycle.cycleSummary(LunaCycle.load()),
      temperature: 0.8,
      maxTokens: 1024,
    };

    abortController = new AbortController();

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: abortController.signal,
      });

      if (res.status === 429) {
        bot.setText('Слишком много сообщений подряд. Сделайте паузу на минуту — и я рядом.');
        return;
      }
      if (!res.ok) {
        let msg = 'Что-то пошло не так. Попробуйте ещё раз.';
        try {
          const j = await res.json();
          if (j && j.error) msg = j.error;
        } catch {}
        bot.setText(msg);
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';
      let finished = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n');
        buffer = parts.pop() || '';
        for (const part of parts) {
          if (!part.startsWith('data: ')) continue;
          let e;
          try { e = JSON.parse(part.slice(6)); } catch { continue; }
          if (e.type === 'token' && typeof e.content === 'string') {
            raw += e.content;
            bot.setText(raw);
          }
          if (e.type === 'error') {
            bot.setText(e.text || 'Ошибка генерации. Попробуйте ещё раз.');
            finished = true;
            break;
          }
          if (e.type === 'done') finished = true;
        }
        if (finished) break;
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        bot.setText(raw || 'Ответ остановлен.');
      } else {
        bot.setText('Не удалось связаться с сервером. Проверьте соединение.');
      }
    } finally {
      bot.bubble.removeAttribute('data-streaming');
      abortController = null;
      setBusy(false);
      if (raw.trim()) {
        history.push({ role: 'assistant', content: raw });
        saveHistory();
      }
      scrollDown();
    }
  }

  function cancel() {
    if (abortController) abortController.abort();
  }

  /* ---- инициализация ---- */

  function init() {
    els.messages = document.getElementById('chat-messages');
    els.input = document.getElementById('chat-input');
    els.send = document.getElementById('chat-send');
    els.cancel = document.getElementById('chat-cancel');
    els.clear = document.getElementById('chat-clear');

    loadHistory();

    if (history.length > 0) {
      for (const m of history) addMessage(m.role === 'user' ? 'user' : 'bot', m.content);
    } else {
      addMessage('bot', 'Здравствуйте, я Луна. Я рядом, чтобы помочь разобраться с вашим циклом, поддержать в непростые дни и — если вы этого захотите — поговорить о том, что живёт глубже тела: о ритмах, душе и внутреннем свете. Как вы себя чувствуете?');
    }
    renderSuggestionChips();

    els.send.addEventListener('click', send);
    els.cancel.addEventListener('click', cancel);
    els.clear.addEventListener('click', () => {
      if (sending) cancel();
      resetHistory();
    });
    els.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        send();
      }
    });
  }

  return { init };
})();

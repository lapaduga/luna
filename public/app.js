'use strict';

/* ===========================================================================
   Интерфейс: вкладки, дашборд, календарь, логирование цикла.
   =========================================================================== */

const LunaApp = (() => {
  let calYear;
  let calMonth;

  const $ = (id) => document.getElementById(id);

  /* ---- луна: SVG-иконки (только наши константы) ---- */
  function moonSvg(kind) {
    const s = '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">';
    switch (kind) {
      case 'new':
        return s + '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/>' + '</svg>';
      case 'full':
        return s + '<circle cx="12" cy="12" r="9" fill="currentColor"/>' + '</svg>';
      case 'quarter':
        return s + '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/>' +
          '<path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor"/></svg>';
      case 'waning':
        return s + '<g transform="rotate(180 12 12)">' +
          '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="currentColor"/></g></svg>';
      default:
        return s + '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="currentColor"/></svg>';
    }
  }

  /* ---- вкладки ---- */
  function switchTab(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    if (name === 'dashboard') renderDashboard();
    if (name === 'calendar') renderCalendar();
  }

  /* ---- дашборд ---- */
  function renderDashboard() {
    const data = LunaCycle.load();
    const s = LunaCycle.stats(data);

    $('phase-name').textContent = s.phaseName;
    $('phase-day').textContent = s.cycleDay
      ? `День цикла ${s.cycleDay}`
      : 'Отметьте первый день менструации, и я начну строить прогнозы';
    $('phase-progress').style.width = (s.progress || 0) + '%';
    $('days-to-next').textContent = s.daysToNext != null ? `через ${s.daysToNext} дн.` : '—';

    $('pred-next').textContent = s.nextStart ? LunaCycle.fmtLong(s.nextStart) : '—';
    $('pred-ovul').textContent = s.ovulation ? LunaCycle.fmtLong(s.ovulation) : '—';
    $('pred-fertile').textContent = (s.fertileStart && s.fertileEnd)
      ? `${LunaCycle.fmtShort(s.fertileStart)} – ${LunaCycle.fmtShort(s.fertileEnd)}`
      : '—';
    $('pred-cycle').textContent = s.avgCycleLength ? `~${s.avgCycleLength} дн.` : '—';

    const moon = LunaCycle.moonPhase();
    $('moon-icon').innerHTML = moonSvg(moon.kind);
    $('moon-name').textContent = moon.name;
    $('moon-guidance').textContent = moon.guidance;

    $('affirmation-text').textContent = LunaCycle.affirmation();
  }

  /* ---- календарь ---- */
  function renderCalendar() {
    const data = LunaCycle.load();
    const marks = LunaCycle.marksForMonth(data, calYear, calMonth);

    const title = new Date(calYear, calMonth, 1)
      .toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' });
    $('cal-title').textContent = title.charAt(0).toUpperCase() + title.slice(1);

    const grid = $('cal-grid');
    grid.replaceChildren();

    const first = new Date(calYear, calMonth, 1);
    const offset = (first.getDay() + 6) % 7; // неделя с понедельника
    const daysInMonth = new Date(calYear, calMonth + 1, 0).getDate();
    const todayISO = LunaCycle.toISO(LunaCycle.today());

    for (let i = 0; i < offset; i++) {
      const blank = document.createElement('div');
      blank.className = 'cal-day blank';
      grid.appendChild(blank);
    }

    for (let d = 1; d <= daysInMonth; d++) {
      const iso = `${calYear}-${String(calMonth + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cal-day';
      btn.setAttribute('aria-label', new Date(calYear, calMonth, d).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' }));

      const set = marks.get(iso);
      if (set) {
        if (set.has('period')) btn.classList.add('m-period');
        if (set.has('predicted')) btn.classList.add('m-predicted');
        if (set.has('fertile')) btn.classList.add('m-fertile');
        if (set.has('ovulation')) btn.classList.add('m-ovulation');
        if (set.has('today')) btn.classList.add('m-today');
      }

      const num = document.createElement('span');
      num.textContent = String(d);
      btn.appendChild(num);
      btn.dataset.iso = iso;
      btn.addEventListener('click', () => openSymptomPanel(iso));
      grid.appendChild(btn);
    }

    renderPeriodsList(data);
  }

  function renderPeriodsList(data) {
    const list = $('periods-list');
    list.replaceChildren();
    if (data.periods.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty-note';
      empty.textContent = 'Записей пока нет. Нажмите «Отметить месячные», когда они начнутся.';
      list.appendChild(empty);
      return;
    }
    const recent = data.periods.slice(-6).reverse();
    for (let i = 0; i < recent.length; i++) {
      const p = recent[i];
      const idx = data.periods.indexOf(p);
      const row = document.createElement('div');
      row.className = 'period-row';

      const info = document.createElement('div');
      info.className = 'period-row-info';
      const label = document.createElement('span');
      label.textContent = p.start === p.end
        ? LunaCycle.fmtLong(LunaCycle.parseISO(p.start))
        : `${LunaCycle.fmtShort(LunaCycle.parseISO(p.start))} – ${LunaCycle.fmtShort(LunaCycle.parseISO(p.end))}`;
      const sub = document.createElement('span');
      sub.className = 'period-row-sub';
      const days = LunaCycle.diffDays(LunaCycle.parseISO(p.start), LunaCycle.parseISO(p.end)) + 1;
      sub.textContent = `${days} дн.` + (p.notes ? ` · ${p.notes}` : '');
      info.appendChild(label);
      info.appendChild(sub);

      const del = document.createElement('button');
      del.type = 'button';
      del.className = 'icon-btn';
      del.setAttribute('aria-label', 'Удалить запись');
      del.textContent = '✕';
      del.addEventListener('click', () => {
        LunaCycle.removePeriod(data, idx);
        renderCalendar();
        renderDashboard();
      });

      row.appendChild(info);
      row.appendChild(del);
      list.appendChild(row);
    }
  }

  /* ---- панели логирования ---- */
  function showPanel(id) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('open'));
    $(id).classList.add('open');
  }
  function hidePanel(id) {
    $(id).classList.remove('open');
  }

  function openPeriodPanel() {
    const todayISO = LunaCycle.toISO(LunaCycle.today());
    $('period-start').value = todayISO;
    $('period-end').value = todayISO;
    $('period-notes').value = '';
    showPanel('panel-period');
  }

  function savePeriod() {
    const data = LunaCycle.load();
    const start = $('period-start').value;
    const end = $('period-end').value || start;
    const notes = $('period-notes').value;
    const res = LunaCycle.addPeriod(data, start, end, notes);
    if (res.error) {
      $('period-notes').placeholder = res.error;
      return;
    }
    hidePanel('panel-period');
    refreshAll();
  }

  function openSymptomPanel(iso) {
    const data = LunaCycle.load();
    const entry = data.daily[iso] || { pain: 0, flow: 0, mood: 0, notes: '' };
    const date = LunaCycle.parseISO(iso);
    $('symptom-date').textContent = date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', weekday: 'short' });
    $('symptom-iso').value = iso;
    setSegmented('pain', entry.pain);
    setSegmented('flow', entry.flow);
    setSegmented('mood', entry.mood);
    $('symptom-notes').value = entry.notes || '';
    showPanel('panel-symptom');
  }

  function setSegmented(name, value) {
    const group = $(`seg-${name}`);
    if (!group) return;
    group.querySelectorAll('.seg-btn').forEach(b => {
      b.classList.toggle('active', Number(b.dataset.val) === Number(value));
    });
  }

  function segValue(name) {
    const group = $(`seg-${name}`);
    if (!group) return 0;
    const active = group.querySelector('.seg-btn.active');
    return active ? Number(active.dataset.val) : 0;
  }

  function saveSymptom() {
    const data = LunaCycle.load();
    const iso = $('symptom-iso').value;
    const entry = {
      pain: segValue('pain'),
      flow: segValue('flow'),
      mood: segValue('mood'),
      notes: $('symptom-notes').value,
    };
    LunaCycle.saveDaily(data, iso, entry);
    hidePanel('panel-symptom');
    refreshAll();
  }

  function refreshAll() {
    renderDashboard();
    renderCalendar();
  }

  /* ---- инициализация ---- */
  function init() {
    const now = LunaCycle.today();
    calYear = now.getFullYear();
    calMonth = now.getMonth();

    document.querySelectorAll('.tab').forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    $('btn-period').addEventListener('click', openPeriodPanel);
    $('btn-chat').addEventListener('click', () => switchTab('chat'));

    $('period-save').addEventListener('click', savePeriod);
    $('period-cancel').addEventListener('click', () => hidePanel('panel-period'));

    $('symptom-save').addEventListener('click', saveSymptom);
    $('symptom-cancel').addEventListener('click', () => hidePanel('panel-symptom'));

    document.querySelectorAll('.seg-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const group = btn.parentElement;
        group.querySelectorAll('.seg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      });
    });

    $('cal-prev').addEventListener('click', () => {
      calMonth--;
      if (calMonth < 0) { calMonth = 11; calYear--; }
      renderCalendar();
    });
    $('cal-next').addEventListener('click', () => {
      calMonth++;
      if (calMonth > 11) { calMonth = 0; calYear++; }
      renderCalendar();
    });
    $('cal-today').addEventListener('click', () => {
      const n = LunaCycle.today();
      calYear = n.getFullYear();
      calMonth = n.getMonth();
      renderCalendar();
    });

    document.querySelectorAll('.panel-close').forEach(btn => {
      btn.addEventListener('click', () => {
        btn.closest('.panel').classList.remove('open');
      });
    });

    renderDashboard();
    renderCalendar();
    LunaChat.init();
  }

  return { init, switchTab };
})();

document.addEventListener('DOMContentLoaded', () => LunaApp.init());

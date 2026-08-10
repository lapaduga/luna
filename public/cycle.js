'use strict';

/* ===========================================================================
   Логика цикла: хранение, прогнозы, фазы, луна, аффирмации.
   Все данные хранятся только в localStorage на устройстве пользовательницы —
   на сервер уходит лишь краткая сводка для контекста чата.
   =========================================================================== */

const LunaCycle = (() => {
  const STORAGE_KEY = 'luna-cycle-data';
  const SYNODIC_MONTH = 29.53058867;

  const defaultData = () => ({
    periods: [], // [{ start: 'YYYY-MM-DD', end: 'YYYY-MM-DD', notes: '' }]
    daily: {},   // { 'YYYY-MM-DD': { pain: 0, flow: 0, mood: 0, notes: '' } }
    settings: { cycleLength: 28, periodLength: 5, luteal: 14 },
  });

  function load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return defaultData();
      const parsed = JSON.parse(raw);
      return {
        ...defaultData(),
        ...parsed,
        settings: { ...defaultData().settings, ...(parsed.settings || {}) },
      };
    } catch {
      return defaultData();
    }
  }

  function save(data) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch (e) {
      console.warn('Не удалось сохранить данные цикла:', e.message);
    }
  }

  /* ---- даты ---- */
  function parseISO(s) {
    const [y, m, d] = String(s).split('-').map(Number);
    return new Date(y, (m || 1) - 1, d || 1);
  }

  function toISO(date) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }

  function addDays(date, n) {
    const d = new Date(date);
    d.setDate(d.getDate() + n);
    return d;
  }

  function diffDays(a, b) {
    const ms = new Date(b.getFullYear(), b.getMonth(), b.getDate()) -
               new Date(a.getFullYear(), a.getMonth(), a.getDate());
    return Math.round(ms / 86400000);
  }

  function fmtLong(date) {
    return date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' });
  }

  function fmtShort(date) {
    return date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' });
  }

  function today() {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return d;
  }

  /* ---- запись данных ---- */
  function addPeriod(data, startISO, endISO, notes) {
    const s = toISO(parseISO(startISO));
    const e = endISO ? toISO(parseISO(endISO)) : s;
    if (diffDays(parseISO(s), parseISO(e)) < 0) return { data, error: 'Конец раньше начала' };
    // Не дублируем пересекающиеся периоды
    const periods = data.periods.filter(p =>
      diffDays(parseISO(s), parseISO(p.end)) > 0 && diffDays(parseISO(p.start), parseISO(e)) < 0
    );
    periods.push({ start: s, end: e, notes: String(notes || '').slice(0, 500) });
    periods.sort((a, b) => a.start < b.start ? -1 : 1);
    data.periods = periods;
    save(data);
    return { data };
  }

  function removePeriod(data, index) {
    if (index >= 0 && index < data.periods.length) {
      data.periods.splice(index, 1);
      save(data);
    }
    return data;
  }

  function saveDaily(data, iso, entry) {
    const clean = {
      pain: Math.max(0, Math.min(3, Number(entry.pain) || 0)),
      flow: Math.max(0, Math.min(3, Number(entry.flow) || 0)),
      mood: Math.max(0, Math.min(3, Number(entry.mood) || 0)),
      notes: String(entry.notes || '').slice(0, 500),
    };
    data.daily[iso] = clean;
    save(data);
    return data;
  }

  /* ---- статистика и прогнозы ---- */
  function stats(data) {
    const starts = data.periods
      .map(p => parseISO(p.start))
      .sort((a, b) => a - b);

    // Средняя длина цикла — медиана интервалов между началами.
    const intervals = [];
    for (let i = 1; i < starts.length; i++) intervals.push(diffDays(starts[i - 1], starts[i]));
    let avgCycle = Number(data.settings.cycleLength) || 28;
    if (intervals.length > 0) {
      const s = [...intervals].sort((a, b) => a - b);
      const mid = Math.floor(s.length / 2);
      avgCycle = s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
    }
    avgCycle = Math.max(21, Math.min(45, avgCycle));

    // Средняя длина менструации.
    let avgPeriod = Number(data.settings.periodLength) || 5;
    const lens = data.periods
      .filter(p => p.end && p.end >= p.start)
      .map(p => diffDays(parseISO(p.start), parseISO(p.end)) + 1)
      .filter(n => n >= 1 && n <= 20);
    if (lens.length > 0) avgPeriod = Math.round(lens.reduce((a, b) => a + b, 0) / lens.length);
    avgPeriod = Math.max(2, Math.min(12, avgPeriod));

    const luteal = Math.max(10, Math.min(17, Number(data.settings.luteal) || 14));
    const todayD = today();
    const lastStart = starts.length ? starts[starts.length - 1] : null;

    let nextStart = lastStart ? addDays(lastStart, avgCycle) : null;
    while (nextStart && diffDays(todayD, nextStart) < 0) nextStart = addDays(nextStart, avgCycle);
    const ovulation = nextStart ? addDays(nextStart, -luteal) : null;
    const fertileStart = ovulation ? addDays(ovulation, -5) : null;
    const fertileEnd = ovulation ? addDays(ovulation, 1) : null;

    // День цикла и фаза.
    let cycleDay = null;
    let phaseName = 'Нет данных';
    if (lastStart) {
      cycleDay = diffDays(lastStart, todayD) + 1;
      if (cycleDay < 1) cycleDay = 1;
    }

    const ovulationDayInCycle = avgCycle - luteal + 1;
    if (cycleDay) {
      if (cycleDay <= avgPeriod) {
        phaseName = 'Менструация';
      } else if (Math.abs(cycleDay - ovulationDayInCycle) <= 1) {
        phaseName = 'Овуляция';
      } else if (cycleDay < ovulationDayInCycle) {
        phaseName = 'Фолликулярная фаза';
      } else {
        phaseName = 'Лютеиновая фаза';
      }
    }

    const daysToNext = nextStart ? diffDays(todayD, nextStart) : null;
    const progress = nextStart && lastStart
      ? Math.max(0, Math.min(100, Math.round(((diffDays(lastStart, todayD) + 1) / avgCycle) * 100)))
      : 0;

    return {
      avgCycleLength: avgCycle,
      avgPeriodLength: avgPeriod,
      cycleDay,
      phaseName,
      lastStart,
      nextStart,
      ovulation,
      fertileStart,
      fertileEnd,
      daysToNext,
      progress,
    };
  }

  /* ---- сводка для контекста чата (только строки) ---- */
  function cycleSummary(data) {
    const s = stats(data);
    const out = {};
    if (s.avgCycleLength) out.avgCycleLength = `${s.avgCycleLength} дней`;
    if (s.avgPeriodLength) out.avgPeriodLength = `${s.avgPeriodLength} дней`;
    if (s.cycleDay) out.cycleDay = String(s.cycleDay);
    if (s.phaseName) out.phaseName = s.phaseName;
    if (s.lastStart) out.lastPeriod = `${fmtLong(s.lastStart)} – ${fmtLong(addDays(s.lastStart, s.avgPeriodLength - 1))}`;
    if (s.nextStart) out.nextPeriod = fmtLong(s.nextStart);
    if (s.ovulation) out.ovulation = fmtLong(s.ovulation);
    if (s.fertileStart && s.fertileEnd) out.fertileWindow = `${fmtShort(s.fertileStart)} – ${fmtShort(s.fertileEnd)}`;
    return out;
  }

  /* ---- луна ---- */
  function moonPhase(date) {
    const d = new Date(date || today());
    d.setHours(0, 0, 0, 0);
    // Известное новолуние: 6 января 2000, 18:14 UTC.
    const ref = Date.UTC(2000, 0, 6, 18, 14, 0);
    let age = ((d.getTime() - ref) / 86400000) % SYNODIC_MONTH;
    if (age < 0) age += SYNODIC_MONTH;
    const pct = age / SYNODIC_MONTH;

    if (pct < 0.02) return { name: 'Новолуние', kind: 'new', guidance: 'Время тишины и новых начал. Загляни внутрь себя.' };
    if (pct < 0.25) return { name: 'Растущий серп', kind: 'waxing', guidance: 'Время намерений: что ты хочешь привнести в свою жизнь?' };
    if (pct < 0.48) return { name: 'Первая четверть', kind: 'waxing', guidance: 'Время действий и движения к своей цели.' };
    if (pct < 0.52) return { name: 'Полнолуние', kind: 'full', guidance: 'Время проявления, благодарности и света.' };
    if (pct < 0.75) return { name: 'Убывающая луна', kind: 'waning', guidance: 'Время отпускать то, что больше не служит тебе.' };
    if (pct < 0.98) return { name: 'Последняя четверть', kind: 'waning', guidance: 'Время завершения, вывода уроков и покоя.' };
    return { name: 'Новолуние', kind: 'new', guidance: 'Время тишины и новых начал. Загляни внутрь себя.' };
  }

  /* ---- аффирмации ---- */
  const AFFIRMATIONS = [
    'Я — целостная. Мой цикл — естественный ритм моего тела, и я могу ему доверять.',
    'Я позволяю себе отдых в те дни, когда моё тело просит покоя.',
    'Моя боль — это сигнал, который я слышу и о котором забочусь.',
    'Я заслуживаю тепла, заботы и доброты — особенно к самой себе.',
    'Моё тело каждый месяц делает огромную работу. Я благодарна ему.',
    'Я вправе проживать свои эмоции, не оправдываясь за них.',
    'Каждая фаза моего цикла — часть меня. Я учусь понимать себя лучше.',
    'Я выбираю заботу о себе без чувства вины.',
    'Моя чувствительность — не слабость, а моя способность слышать себя.',
    'Я дышу медленно и спокойно. Моё тело расслабляется, я в безопасности.',
    'Я не обязана быть продуктивной каждый день. Моя ценность не зависит от дел.',
    'Я — свет для самой себя, даже когда вокруг темно.',
  ];

  function affirmation(date) {
    const d = date || today();
    const dayNum = Math.floor(d.getTime() / 86400000);
    return AFFIRMATIONS[((dayNum % AFFIRMATIONS.length) + AFFIRMATIONS.length) % AFFIRMATIONS.length];
  }

  /* ---- разметка календаря: какие дни помечаем ---- */
  function marksForMonth(data, year, month) {
    const s = stats(data);
    const todayISO = toISO(today());
    const marks = new Map(); // iso -> {type: 'period'|'predicted'|'fertile'|'ovulation'|'today', }

    const add = (iso, type) => {
      const cur = marks.get(iso);
      if (!cur) marks.set(iso, new Set([type]));
      else cur.add(type);
    };

    // зарегистрированные менструации
    for (const p of data.periods) {
      let d = parseISO(p.start);
      const end = parseISO(p.end || p.start);
      while (diffDays(d, end) >= 0) {
        add(toISO(d), 'period');
        d = addDays(d, 1);
      }
    }

    // прогноз следующей менструации
    if (s.nextStart) {
      for (let i = 0; i < s.avgPeriodLength; i++) add(toISO(addDays(s.nextStart, i)), 'predicted');
    }
    // фертильное окно и овуляция
    if (s.fertileStart && s.fertileEnd) {
      let d = s.fertileStart;
      const end = s.fertileEnd;
      while (diffDays(d, end) >= 0) {
        add(toISO(d), 'fertile');
        d = addDays(d, 1);
      }
    }
    if (s.ovulation) add(toISO(s.ovulation), 'ovulation');

    add(todayISO, 'today');
    return marks;
  }

  return {
    load, save, addPeriod, removePeriod, saveDaily,
    stats, cycleSummary, moonPhase, affirmation, marksForMonth,
    parseISO, toISO, addDays, diffDays, fmtLong, fmtShort, today,
  };
})();

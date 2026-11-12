'use strict';
/* Вес конкурса (0–100) и баллы за результат.
   Формула из BACKEND.md, совпадает с contestWeight() в app.js. */

const LEVELS = {
  school:   { label: 'Школьный',        base: 20 },
  city:     { label: 'Городской',       base: 35 },
  region:   { label: 'Областной',       base: 55 },
  national: { label: 'Республиканский', base: 75 },
  intl:     { label: 'Международный',   base: 85 },
};

const RESULTS = {
  winner:      { label: 'Победитель', k: 1 },
  prize:       { label: 'Призёр',     k: 0.7 },
  finalist:    { label: 'Финалист',   k: 0.4 },
  participant: { label: 'Участник',   k: 0.15 },
};

function contestWeight(c, org) {
  const verified = c.orgVerified !== undefined ? c.orgVerified : !!(org && org.verified);
  const parts = [];
  const lvl = LEVELS[c.level] || LEVELS.city;
  parts.push([`Уровень: ${lvl.label.toLowerCase()}`, lvl.base]);
  const size = Math.round(Math.min(15, Math.log10(Math.max(+c.participants || 1, 1)) * 5));
  parts.push([`${(+c.participants || 1).toLocaleString('ru-RU')} участников`, size]);
  if (c.selection) parts.push(['Есть отборочный этап', 10]);
  if (!verified) parts.push(['Организатор не подтверждён', -30]);
  if (c.paid && !c.selection) parts.push(['Платное участие без отбора', -25]);
  if (+c.awarded > 50) parts.push([`Наградили ${c.awarded}% участников`, -20]);
  const total = Math.max(0, Math.min(100, parts.reduce((a, p) => a + p[1], 0)));
  return { total, parts };
}

const certPoints = (weightTotal, result) => Math.round(weightTotal * (RESULTS[result] || RESULTS.participant).k);

module.exports = { LEVELS, RESULTS, contestWeight, certPoints };

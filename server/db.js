'use strict';
/* Хранилище Proofy: JSON-файл server/data/db.json.
   Локальный аналог таблиц PostgreSQL из BACKEND.md.
   Закрытые ключи организаторов лежат в отдельном разделе db.keys
   (в рабочей версии — env/KMS, не в таблице orgs). */
const fs = require('node:fs');
const path = require('node:path');
const { genKeys, signCert, sha256hex } = require('./crypto');

const DATA_FILE = process.env.PROOFY_DATA_FILE || path.join(__dirname, 'data', 'db.json');

/* Демо-аккаунты: роли, логин, пароль. В БД хранятся ТОЛЬКО SHA-256-хеши
   токенов (токен — это и есть «пароль» аккаунта, выдаётся при входе). */
const DEMO_ACCOUNTS = [
  { role: 'student', entity: 's1', login: 'aigerim', pass: 'pfy_demo_s1' },
  { role: 'student', entity: 's2', login: 'daniyar', pass: 'pfy_demo_s2' },
  { role: 'student', entity: 's3', login: 'madina', pass: 'pfy_demo_s3' },
  { role: 'student', entity: 's4', login: 'timur', pass: 'pfy_demo_s4' },
  { role: 'student', entity: 's5', login: 'aruzhan', pass: 'pfy_demo_s5' },
  { role: 'student', entity: 's6', login: 'erlan', pass: 'pfy_demo_s6' },
  { role: 'org', entity: 'o1', login: 'gambit', pass: 'pfy_demo_o1' },
  { role: 'org', entity: 'o2', login: 'edu', pass: 'pfy_demo_o2' },
  { role: 'org', entity: 'o3', login: 'center', pass: 'pfy_demo_o3' },
  { role: 'org', entity: 'o4', login: 'starolympiad', pass: 'pfy_demo_o4' },
  { role: 'buyer', entity: 'b1', login: 'bilim', pass: 'pfy_demo_b1' },
  { role: 'buyer', entity: 'b2', login: 'univer', pass: 'pfy_demo_b2' },
];

/* Резюме тестовых школьников — копия PROFILES из app.js (данные тестовые) */
const PROFILES = {
  s1: { headline: 'Пишет на Python и делает Telegram-ботов', fame: 'Победила на Gambit Hackathon 2026', about: 'Сделала бота школьного расписания, им пользуются 600 учеников. Хочет учиться на программиста.', skills: ['Python', 'Telegram-боты', 'Figma'], projects: [['Бот расписания', 'Telegram-бот для 600 учеников школы']] },
  s2: { headline: 'Капитан команды по робототехнике', fame: 'Привёл команду к победе на областном турнире FTC', about: 'Собирает роботов с 8 класса и учит младших программировать на C++.', skills: ['C++', 'Arduino', 'CAD'], projects: [['Робот-сортировщик', 'Робот для турнира FTC, собран за 6 недель']] },
  s3: { headline: 'Олимпиадная математика', fame: 'Победительница областной олимпиады по математике', about: 'Решает задачи по комбинаторике и бесплатно ведёт кружок для младших.', skills: ['Комбинаторика', 'Геометрия', 'Теория чисел'], projects: [['Кружок для младших', 'Занятия для учеников 5–7 классов']] },
  s4: { headline: 'Спортивное программирование', fame: 'Победитель республиканской олимпиады по информатике', about: 'Готовится к международной олимпиаде.', skills: ['C++', 'Алгоритмы'], projects: [] },
  s5: { headline: 'Инженер-конструктор', fame: 'Призёр областного турнира FTC', about: 'Проектирует детали в CAD и печатает их на 3D-принтере.', skills: ['3D-печать', 'CAD', 'Электроника'], projects: [['Протез-манипулятор', 'Прототип кисти руки из 3D-печати']] },
  s6: { headline: 'Любит алгебру', fame: 'Участник областной олимпиады по математике', about: 'Готовится к областной олимпиаде следующего года.', skills: ['Алгебра'], projects: [] },
};
const profileOf = (id) => JSON.parse(JSON.stringify(PROFILES[id] || { headline: '', fame: '', about: '', skills: [], projects: [] }));

/* Сид-данные: 1-в-1 с seed() из app.js. ID сертификатов должны совпадать
   с напечатанными карточками для питча (PRF-GH26-0001, PRF-OM26-0003, PRF-GH26-0999 не существует). */
function seed() {
  const db = {
    orgs: [
      { id: 'o1', name: 'Gambit Hackathon (HackHub)', city: 'Актобе', verified: true },
      { id: 'o2', name: 'Управление образования области (тест)', city: 'Актобе', verified: true },
      { id: 'o3', name: 'Республиканский центр олимпиад (тест)', city: 'Астана', verified: true },
      { id: 'o4', name: 'Star Olympiad International (онлайн)', city: '—', verified: false },
    ],
    contests: [
      { id: 'k1', code: 'GH26', orgId: 'o1', name: 'Gambit Hackathon 2026', direction: 'IT', level: 'region', participants: 300, selection: true, paid: false, awarded: 10, date: '2026-11-14', next: 4 },
      { id: 'k2', code: 'OM26', orgId: 'o2', name: 'Областная олимпиада по математике', direction: 'Математика', level: 'region', participants: 1200, selection: true, paid: false, awarded: 8, date: '2026-02-20', next: 4 },
      { id: 'k3', code: 'RI26', orgId: 'o3', name: 'Республиканская олимпиада по информатике', direction: 'IT', level: 'national', participants: 2500, selection: true, paid: false, awarded: 5, date: '2026-04-10', next: 3 },
      { id: 'k4', code: 'SO26', orgId: 'o4', name: 'Star Olympiad — математика', direction: 'Математика', level: 'intl', participants: 5000, selection: false, paid: true, awarded: 85, date: '2026-03-01', next: 3 },
      { id: 'k5', code: 'FT26', orgId: 'o2', name: 'Областной турнир по робототехнике FTC', direction: 'Робототехника', level: 'region', participants: 160, selection: true, paid: false, awarded: 15, date: '2026-03-15', next: 3 },
    ],
    students: [
      { id: 's1', name: 'Айгерим Нурланова', grade: 10, city: 'Хромтау', school: 'Школа-гимназия №1', direction: 'IT', parent: true, search: true, showName: false, portfolio: true, contact: 'aigerim.test@example.com' },
      { id: 's2', name: 'Данияр Сапаров', grade: 11, city: 'Актобе', school: 'НИШ (тест)', direction: 'Робототехника', parent: true, search: true, showName: true, portfolio: true, contact: 'daniyar.test@example.com' },
      { id: 's3', name: 'Мадина Ержанова', grade: 9, city: 'Шалкар', school: 'СОШ №2', direction: 'Математика', parent: true, search: true, showName: false, portfolio: false, contact: 'madina.test@example.com' },
      { id: 's4', name: 'Тимур Ахметов', grade: 11, city: 'Алматы', school: 'Лицей №165 (тест)', direction: 'IT', parent: false, search: false, showName: false, portfolio: false, contact: 'timur.test@example.com' },
      { id: 's5', name: 'Аружан Кайратова', grade: 10, city: 'Кандыагаш', school: 'СОШ №5', direction: 'Робототехника', parent: true, search: true, showName: true, portfolio: true, contact: 'aruzhan.test@example.com' },
      { id: 's6', name: 'Ерлан Беков', grade: 10, city: 'Эмба', school: 'СОШ №1', direction: 'Математика', parent: true, search: true, showName: false, portfolio: false, contact: 'erlan.test@example.com' },
    ],
    certs: [
      { id: 'PRF-GH26-0001', contestId: 'k1', studentId: 's1', result: 'winner' },
      { id: 'PRF-RI26-0001', contestId: 'k3', studentId: 's1', result: 'prize' },
      { id: 'PRF-GH26-0002', contestId: 'k1', studentId: 's2', result: 'prize' },
      { id: 'PRF-FT26-0001', contestId: 'k5', studentId: 's2', result: 'winner' },
      { id: 'PRF-OM26-0001', contestId: 'k2', studentId: 's3', result: 'winner' },
      { id: 'PRF-SO26-0001', contestId: 'k4', studentId: 's3', result: 'winner' },
      { id: 'PRF-OM26-0002', contestId: 'k2', studentId: 's4', result: 'prize' },
      { id: 'PRF-RI26-0002', contestId: 'k3', studentId: 's4', result: 'winner' },
      { id: 'PRF-FT26-0002', contestId: 'k5', studentId: 's5', result: 'prize' },
      { id: 'PRF-GH26-0003', contestId: 'k1', studentId: 's5', result: 'participant' },
      { id: 'PRF-SO26-0002', contestId: 'k4', studentId: 's6', result: 'winner' },
      { id: 'PRF-OM26-0003', contestId: 'k2', studentId: 's6', result: 'participant' },
    ],
    buyers: [
      { id: 'b1', name: 'Агентство «Bilim Path» (тест)', type: 'Образовательное агентство' },
      { id: 'b2', name: 'Приёмная комиссия, региональный вуз (тест)', type: 'Вуз' },
    ],
    requests: [
      { id: 'r1', buyerId: 'b1', studentId: 's1', purpose: 'Консультация по поступлению', status: 'pending', date: '2026-11-11' },
      { id: 'r2', buyerId: 'b2', studentId: 's2', purpose: 'Грант на обучение', status: 'approved', date: '2026-11-10' },
    ],
    /* Аккаунты: { id, role, entityId, login, tokenHash } — хеш, сырые пароли не храним */
    accounts: DEMO_ACCOUNTS.map((a, i) => ({
      id: 'u' + (i + 1), role: a.role, entityId: a.entity, login: a.login,
      tokenHash: sha256hex(a.pass),
    })),
    checks: 0,
    seq: 100,
  };

  for (const s of db.students) s.profile = profileOf(s.id);

  db.keys = {};
  for (const o of db.orgs) db.keys[o.id] = genKeys();
  for (const c of db.certs) {
    c.issuedAt = new Date().toISOString();
    signCert(db, c);
  }
  db.createdAt = new Date().toISOString();
  return db;
}

function load() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (db && Array.isArray(db.orgs) && Array.isArray(db.certs)) {
        /* Миграция старей версии: демо-сессия и API-ключи покупателей удалены (RBAC: вход по токенам) */
        if (!Array.isArray(db.accounts)) db = seed();
        delete db.session;
        for (const b of db.buyers) delete b.apiKeyHash;
        return db;
      }
    }
  } catch (e) {
    console.warn('[proofy] db.json повреждён — пересоздаю сид-данные:', e.message);
  }
  const db = seed();
  save(db);
  return db;
}

function save(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

module.exports = { load, save, seed, DATA_FILE, DEMO_ACCOUNTS, PROFILES };

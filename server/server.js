'use strict';
/* =====================================================================
   Proofy — настоящий бэкенд прототипа (спецификация: BACKEND.md).
   Стек: Node.js без внешних зависимостей (node:http + node:crypto).
   Хранилище: server/data/db.json (локальный аналог PostgreSQL).

   Запуск:  node server/server.js
   Адрес:   http://localhost:4173  — сервер отдаёт и API, и фронтенд.
   Env:     PORT (4173), HOST (0.0.0.0), CORS_ORIGIN (*)
   ===================================================================== */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { load, save, seed, DEMO_ACCOUNTS } = require('./db');

/* Сервер не должен молча умирать: любой сбой фиксируем в stderr */
process.on('uncaughtException', (e) => { console.error('[fatal] uncaughtException:', e && e.stack || e); });
process.on('unhandledRejection', (e) => { console.error('[fatal] unhandledRejection:', e && e.stack || e); });
process.on('clientError', (e, sock) => {
  /* некорректный HTTP-запрос (в т.ч. от сканеров): вежливый 400, сервер не роняется */
  if (sock.writable) { try { sock.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'); } catch (err) { sock.destroy(); } }
  else sock.destroy();
});
const { genKeys, signCert, verifyCertSig } = require('./crypto');
const { LEVELS, RESULTS, contestWeight, certPoints } = require('./weight');

const PORT = +(process.env.PORT || 4173);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = path.resolve(__dirname, '..');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

let db = load();

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const today = () => new Date().toISOString().slice(0, 10);
const initials = (name) => String(name || '').split(/\s+/).filter(Boolean).map((p) => p[0] + '.').join(' ');
const commit = () => save(db);

const contestOf = (id) => db.contests.find((x) => x.id === id);
const orgOf = (id) => db.orgs.find((x) => x.id === id);
const studentOf = (id) => db.students.find((x) => x.id === id);
const weightOf = (k) => contestWeight(k, orgOf(k.orgId));

function ratingOf(sid) {
  return db.certs.filter((c) => c.studentId === sid).reduce((a, c) => {
    const k = contestOf(c.contestId);
    return k ? a + certPoints(weightOf(k).total, c.result) : a;
  }, 0);
}
function bestWeightOf(sid) {
  const ks = db.certs.filter((c) => c.studentId === sid).map((c) => contestOf(c.contestId)).filter(Boolean);
  return ks.length ? Math.max(...ks.map((k) => weightOf(k).total)) : 0;
}

/* ---------------- Ответы и запросы ---------------- */
function sendJson(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': CORS_ORIGIN,
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(obj));
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const ch of req) {
    size += ch.length;
    if (size > 1e6) throw new Error('body too large');
    chunks.push(ch);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) { return {}; }
}

/* Публичные ключи организаторов (только kid + открытый JWK — закрытых частей нет) */
function publicKeys() {
  const keys = {};
  for (const [id, k] of Object.entries(db.keys || {})) keys[id] = { kid: k.kid, pub: k.pub };
  return keys;
}

/* ---------------- RBAC ----------------
   Токен = Bearer-строка; в БД — только SHA-256 хеш (db.accounts[].tokenHash).
   Роли: anon | student | org | buyer. Каждый обработчик проверяет и роль, и
   владение сущностью (школьник — только свои данные, орг — только свои конкурсы
   и сертификаты своих конкурсов, покупатель — только поиск и СВОИ запросы). */
function principalFromAuth(req) {
  const h = req.headers['authorization'] || '';
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  if (!m) return { role: 'anon', entityId: null, account: null };
  const hash = sha256(m[1].trim());
  const acc = (db.accounts || []).find((x) => x.tokenHash === hash);
  if (!acc) return { __invalid: true };
  return { role: acc.role, entityId: acc.entityId, account: acc };
}
const requireRole = (pr, ...roles) => (!pr.__invalid && roles.includes(pr.role) ? null : [401, { error: 'требуется вход', need: roles }]);
const ownOr403 = (pr, id) => (pr.entityId === id ? null : [403, { error: 'доступ к чужому аккаунту запрещён' }]);

/* Имя сущности роли (для /v1/me и /v1/accounts) */
function entityName(role, id) {
  const e = role === 'student' ? studentOf(id) : role === 'org' ? orgOf(id) : role === 'buyer' ? db.buyers.find((x) => x.id === id) : null;
  return e ? e.name : null;
}

/* Публичная статистика и публичный каталог (без входа): для главной, рейтинга, API-страницы */
function publicStats() {
  const visible = db.students.filter((s) => s.parent && s.search);
  const cities = new Set(visible.map((s) => s.city).filter(Boolean));
  const byCity = {};
  visible.forEach((s) => { if (s.city) byCity[s.city] = (byCity[s.city] || 0) + 1; });
  return {
    certs: db.certs.length,
    contests: db.contests.length,
    orgs: db.orgs.map((o) => ({ id: o.id, name: o.name, city: o.city, verified: o.verified })),
    keys: publicKeys(),
    visible_talents: visible.length,
    hidden_talents: db.students.length - visible.length,
    visible_by_city: byCity,
    cities: [...cities],
    /* публичное резюме конкурсов (вес открытая формула) — для рейтинга и рекомендаций */
    contest_summaries: db.contests.map((k) => ({ id: k.id, name: k.name, direction: k.direction, level: k.level, weight: weightOf(k).total })),
  };
}

/* Ролевой срез состояния: НЕМНОГО — ровно то, что роли разрешено.
   student: свои данные + чужое имя покупателя по своим запросам.
   org:     свои конкурсы + сертификаты своих конкурсов (школьники — только имя/класс/город/школа).
   buyer:   свои запросы + школьники по своим запросам (имя/контакт — только при одобрении). */
function roleState(pr) {
  const stats = publicStats();
  const base = { role: pr.role, stats, keys: stats.keys, seq: db.seq };
  if (pr.role === 'student') {
    const me = studentOf(pr.entityId);
    if (!me) return [404, { error: 'аккаунт не найден' }];
    const ownCerts = db.certs.filter((c) => c.studentId === me.id);
    const ownContestIds = new Set(ownCerts.map((c) => c.contestId));
    const ownReqs = db.requests.filter((r) => r.studentId === me.id);
    const buyerIds = new Set(ownReqs.map((r) => r.buyerId));
    /* КАТАЛОГ для школьника: ВСЕ конкурсы (не только свои — выбирать, куда участвовать),
       все организаторы и все вузы (кто ищет таланты). Приватного нет: контактов покупателей не отдаём. */
    const allContests = db.contests.map(publicContest);
    const catalogOrgs = db.orgs.map((o) => ({ id: o.id, name: o.name, city: o.city, verified: o.verified }));
    const catalogBuyers = db.buyers.map((b) => ({ id: b.id, name: b.name, type: b.type }));
    return [200, Object.assign(base, {
      me,
      students: [me],
      certs: ownCerts,
      contests: allContests,
      orgs: catalogOrgs,
      buyers: catalogBuyers,
      requests: ownReqs,
    })];
  }
  if (pr.role === 'org') {
    const me = orgOf(pr.entityId);
    if (!me) return [404, { error: 'аккаунт не найден' }];
    const ownContests = db.contests.filter((k) => k.orgId === me.id);
    const ids = new Set(ownContests.map((k) => k.id));
    const ownCerts = db.certs.filter((c) => ids.has(c.contestId));
    const studIds = new Set(ownCerts.map((c) => c.studentId));
    const studentRefs = db.students.filter((s) => studIds.has(s.id)).map((s) => ({ id: s.id, name: s.name, grade: s.grade, city: s.city, school: s.school }));
    /* запросы, которые орг отправил школьникам из поиска (buyerId = id просящего),
       + все вузы — каталог, чтобы видеть, кто ищет таланты */
    const ownReqs = db.requests.filter((r) => r.buyerId === me.id);
    const catalogBuyers = db.buyers.map((b) => ({ id: b.id, name: b.name, type: b.type }));
    return [200, Object.assign(base, {
      me,
      orgs: [me],
      contests: ownContests,
      certs: ownCerts,
      students: studentRefs,
      buyers: catalogBuyers,
      requests: ownReqs,
    })];
  }
  if (pr.role === 'buyer') {
    const me = db.buyers.find((x) => x.id === pr.entityId);
    if (!me) return [404, { error: 'аккаунт не найден' }];
    const ownReqs = db.requests.filter((r) => r.buyerId === me.id);
    const studIds = new Set(ownReqs.map((r) => r.studentId));
    const studentRefs = db.students.filter((s) => studIds.has(s.id)).map((s) => {
      const approved = ownReqs.some((r) => r.studentId === s.id && r.status === 'approved');
      const r = { id: s.id, grade: s.grade, city: s.city, school: s.school };
      if (s.showName || approved) r.name = s.name;
      if (approved) r.contact = s.contact; /* контакт — только одобренному запросу этого покупателя */
      return r;
    });
    return [200, Object.assign(base, {
      me,
      buyers: [me],
      students: studentRefs,
      certs: [],
      contests: [],
      orgs: db.orgs.map((o) => ({ id: o.id, name: o.name, city: o.city, verified: o.verified })),
      requests: ownReqs,
    })];
  }
  return [401, { error: 'требуется вход' }];
}

/* POST /v1/login — вход: {login, password}. В ответе — токен (в демо пароль = токен). */
function loginHandler(body) {
  const login = String(body.login || '').trim().toLowerCase();
  const password = String(body.password || '').trim();
  if (!login || !password) return [400, { error: 'login и password обязательны' }];
  const acc = (db.accounts || []).find((x) => x.login.toLowerCase() === login);
  if (!acc || acc.tokenHash !== sha256(password)) return [401, { error: 'неверный логин или пароль' }];
  return [200, { token: password, account: { id: acc.id, role: acc.role, entityId: acc.entityId, name: entityName(acc.role, acc.entityId) } }];
}

/* GET /v1/accounts — демо-каталог аккаунтов (для страницы входа) */
function accountsHandler() {
  /* демо-режим: токен == пароль, поэтому фронт может подставить поля одной кнопкой.
     В рабочей версии пароль ни в коем случае не отдаётся. */
  const byLogin = {};
  for (const a of DEMO_ACCOUNTS) byLogin[a.login] = a.pass;
  const list = (db.accounts || []).map((a) => ({ role: a.role, entityId: a.entityId, login: a.login, name: entityName(a.role, a.entityId), pass: byLogin[a.login] || null }));
  return [200, { accounts: list }];
}

/* GET /v1/me — кто я (по токenu) */
function meHandler(pr) {
  if (pr.role === 'anon') return [401, { error: 'требуется вход' }];
  return [200, { role: pr.role, entityId: pr.entityId, name: entityName(pr.role, pr.entityId) }];
}

/* GET /v1/portfolio/{sid} — резюме таланта.
   Публично — если включено public_portfolio; покупателю — если parent_consent AND in_search.
   Контакт — только если покупатель одобрен запросом. */
function portfolioHandler(sid, pr) {
  const s = studentOf(sid);
  if (!s) return [404, { error: 'резюме не найдено' }];
  const buyerAllowed = pr.role === 'buyer' && s.parent && s.search;
  if (!s.portfolio && !buyerAllowed) return [403, { error: 'резюме скрыто' }];
  const approved = buyerAllowed && db.requests.some((r) => r.buyerId === pr.entityId && r.studentId === s.id && r.status === 'approved');
  const req = buyerAllowed ? db.requests.find((r) => r.buyerId === pr.entityId && r.studentId === s.id) : null;
  const display_name = approved || s.showName ? s.name : `Школьник, ${s.grade} класс`;
  return [200, {
    student: {
      id: s.id, display_name, name: (approved || s.showName) ? s.name : null, initials: initials(s.name), show_name: !!s.showName, portfolio: !!s.portfolio,
      grade: s.grade, city: s.city, school: buyerAllowed || s.showName ? s.school : null,
      direction: s.direction, profile: s.profile || { headline: '', fame: '', about: '', skills: [], projects: [] },
    },
    points: ratingOf(s.id),
    achievements: db.certs.filter((c) => c.studentId === s.id).map((c) => {
      const k = contestOf(c.contestId);
      return {
        cert_id: c.id, result: c.result,
        contest_id: k.id, contest_name: k.name, contest_weight: weightOf(k).total,
        org_name: orgOf(k.orgId).name, org_verified: orgOf(k.orgId).verified, date: k.date,
      };
    }),
    request: req ? { id: req.id, status: req.status, purpose: req.purpose } : null,
    contact: approved ? s.contact : null,
  }];
}

/* ---------------- Обработчики /v1 ---------------- */

/* GET /v1/certificates/{id}/verify?claimed_result= — публично (для сканера QR) */
function verifyHandler(id, query, pr) {
  db.checks++;
  const cert = db.certs.find((c) => c.id === String(id).toUpperCase());
  if (!cert) { commit(); return [404, { found: false }]; }
  const k = contestOf(cert.contestId);
  const o = orgOf(k.orgId);
  const s = studentOf(cert.studentId);
  const claim = query.get('claimed_result') || '';
  const sigOk = verifyCertSig(db, cert);
  const claimSigOk = claim && claim !== cert.result ? verifyCertSig(db, cert, claim) : null;
  const w = weightOf(k);
  commit();
  return [200, {
    found: true,
    cert: {
      id: cert.id, contest_id: k.id, contestId: k.id,
      student_id: s.id, studentId: s.id, result: cert.result,
      signature: cert.sig, sig: cert.sig, key_id: cert.kid, kid: cert.kid,
      issued_at: cert.issuedAt || null,
    },
    holder: { display_name: s.showName ? s.name : initials(s.name), name: s.showName ? s.name : null, initials: initials(s.name), show_name: !!s.showName, grade: s.grade, city: s.city, contact: null },
    contest: {
      id: k.id, name: k.name, level: k.level, direction: k.direction,
      participants: k.participants, selection: k.selection, paid: k.paid,
      awarded: k.awarded, date: k.date, weight: w.total, weight_parts: w.parts,
    },
    org: { id: o.id, name: o.name, verified: o.verified },
    sig_ok: sigOk, sigOk,
    claimed_result_sig_ok: claimSigOk, claimSigOk,
    intact: true,
    points: certPoints(w.total, cert.result),
  }];
}

/* POST /v1/contests — новый конкурс (ТОЛЬКО организатор, в его аккаунт) */
function createContestHandler(body, pr) {
  const o = orgOf(pr.entityId);
  if (!o) return [404, { error: 'организатор не найден' }];
  const name = String(body.name || '').trim();
  if (!name) return [400, { error: 'name обязателен' }];
  const k = {
    id: 'k' + (++db.seq), code: 'NK' + String(db.seq).slice(-2), next: 1,
    orgId: o.id, name,
    direction: body.direction || 'IT',
    level: LEVELS[body.level] ? body.level : 'city',
    participants: Math.max(1, +body.participants || 1),
    awarded: Math.min(100, Math.max(0, +body.awarded || 0)),
    date: body.date || today(),
    selection: !!body.selection,
    paid: !!body.paid,
  };
  db.contests.push(k);
  commit();
  return [201, { contest: k }];
}

/* POST /v1/contests/{id}/certificates — выдача пачкой (ТОЛЬКО организатор-владелец конкурса) */
function issueHandler(contestId, body, pr) {
  const k = contestOf(contestId);
  if (!k) return [404, { error: 'конкурс не найден' }];
  if (k.orgId !== pr.entityId) return [403, { error: 'чужой конкурс: выдача запрещена' }];
  const rows = Array.isArray(body.rows) ? body.rows : [];
  if (!rows.length) return [400, { error: 'rows: нужен непустой список' }];
  /* Пред-валидация всех строк: выдача атомарна — при ошибке в любой строке ничего не создаётся */
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i] || {};
    const name = String(r.name || '').trim();
    const grade = +r.grade;
    if (!name || !RESULTS[r.result] || !(grade >= 1 && grade <= 11)) {
      return [400, { error: `строка ${i + 1}: нужны ФИО, класс 1–11 и результат (winner|prize|finalist|participant)` }];
    }
  }
  const ids = [];
  for (const r of rows) {
    const name = String(r.name || '').trim();
    const grade = +r.grade;
    const result = r.result;
    /* Ищем по (name, school); нет — создаём скрытого школьника (все согласия = false) */
    let s = db.students.find((x) =>
      x.name.toLowerCase() === name.toLowerCase() &&
      String(x.school || '').toLowerCase() === String(r.school || '').toLowerCase());
    if (!s) {
      s = {
        id: 's' + (++db.seq), name, grade,
        city: String(r.city || ''), school: String(r.school || ''),
        direction: k.direction,
        parent: false, search: false, showName: false, portfolio: false,
        contact: `student${db.seq}.test@example.com`,
        profile: { headline: '', fame: '', about: '', skills: [], projects: [] },
      };
      db.students.push(s);
    }
    const cert = {
      id: `PRF-${k.code}-${String(k.next++).padStart(4, '0')}`,
      contestId: k.id, studentId: s.id, result,
      issuedAt: new Date().toISOString(),
    };
    signCert(db, cert);
    db.certs.push(cert);
    ids.push(cert.id);
  }
  commit();
  return [201, { issued: ids }];
}

/* Публичное описание конкурса (для каталога, рейтинга и #/k/{id}) */
function publicContest(k) {
  const o = orgOf(k.orgId);
  const w = weightOf(k);
  return {
    id: k.id, code: k.code, name: k.name, direction: k.direction, level: k.level,
    participants: k.participants, date: k.date,
    selection: k.selection, paid: k.paid, awarded: k.awarded, next: k.next,
    org: { id: o.id, name: o.name, verified: o.verified },
    orgId: o.id,
    weight: w.total, weight_parts: w.parts,
    awarded_count: db.certs.filter((c) => c.contestId === k.id).length,
  };
}

/* GET /v1/contests?direction=&selection= — каталог/рейтинг конкурсов с весом (публично) */
function contestsHandler(query) {
  const dir = query.get('direction') || '';
  const sel = query.get('selection');
  const list = db.contests
    .filter((k) => (!dir || k.direction === dir) && (sel !== '1' && sel !== '0' ? true : (sel === '1') === !!k.selection))
    .map(publicContest)
    .sort((a, b) => b.weight - a.weight);
  return [200, { contests: list }];
}

/* GET /v1/hackathons — каталог хакатонов (конкурсы с отборочным/соревновательным этапом),
   публично: для школьника и для витрины «Каталог хакатонов». */
function hackathonsHandler() {
  const list = db.contests
    .filter((k) => k.selection)
    .map(publicContest)
    .sort((a, b) => (a.date > b.date ? -1 : 1)); /* сначала ближайшие даты */
  return [200, { hackathons: list }];
}

/* GET /v1/contests/{id} — деталь конкурса (публично) */
function contestByIdHandler(id) {
  const k = contestOf(id);
  if (!k) return [404, { error: 'конкурс не найден' }];
  return [200, { contest: publicContest(k) }];
}

/* GET /v1/orgs/{id}/public-key — открытый ключ (JWK) */
function publicKeyHandler(orgId) {
  const ks = db.keys && db.keys[orgId];
  if (!ks) return [404, { error: 'организатор не найден' }];
  return [200, { kid: ks.kid, jwk: ks.pub }];
}

/* GET /v1/talents?city=&direction=&min_weight= — ТОЛЬКО покупатель ИЛИ организатор.
   Только parent_consent AND in_search; контакт — по одобренному запросу ЭТОГО просителя. */
function talentsHandler(query, pr) {
  /* (покупатель больше не нужен напрямую: запросы хранят buyerId = entityId просителя) */
  const city = query.get('city') || '';
  const dir = query.get('direction') || '';
  const minW = +(query.get('min_weight') || 0);
  const visible = db.students.filter((s) => s.parent && s.search);
  const talents = visible
    .filter((s) =>
      (!city || s.city === city) &&
      (!dir || s.direction === dir || db.certs.some((c) => c.studentId === s.id && contestOf(c.contestId) && contestOf(c.contestId).direction === dir)) &&
      bestWeightOf(s.id) >= minW)
    .map((s) => {
      /* запрос может прийти и от вуза, и от организатора — контакт откроется после одобрения школьником.
         Статус конкретного запроса фронт видит в своём срезе (db.requests), здесь — только факт открытого контакта. */
      const open = db.requests.some((r) => r.buyerId === pr.entityId && r.studentId === s.id && r.status === 'approved');
      return {
        id: s.id,
        display_name: s.showName ? s.name : initials(s.name),
        grade: s.grade, city: s.city, direction: s.direction,
        points: ratingOf(s.id), best_weight: bestWeightOf(s.id),
        portfolio: !!s.portfolio,
        achievements_count: db.certs.filter((c) => c.studentId === s.id).length,
        contact_open: open, /* контакт отдаётся только после одобренного запроса этого покупателя */
      };
    })
    .sort((a, b) => b.points - a.points);
  return [200, { talents, hidden_count: db.students.length - visible.length }];
}

/* POST /v1/contact-requests — запрос контакта (ТОЛЬКО покупатель ИЛИ организатор; проситель = владелец токена).
   Поле buyerId хранит id просителя (вуза ИЛИ орг-а) — фронт понимает роль по аккаунту. */
function createRequestHandler(body, pr) {
  if (pr.role === 'buyer') { if (!db.buyers.some((x) => x.id === pr.entityId)) return [404, { error: 'покупатель не найден' }]; }
  else if (pr.role === 'org') { if (!orgOf(pr.entityId)) return [404, { error: 'организатор не найден' }]; }
  else return [401, { error: 'нужен вход' }];
  const s = studentOf(String(body.studentId || ''));
  if (!s) return [404, { error: 'школьник не найден' }];
  if (!s.parent || !s.search) return [403, { error: 'школьник не в поиске (нет согласия)' }];
  const r = { id: 'r' + (++db.seq), buyerId: pr.entityId, studentId: s.id, purpose: String(body.purpose || ''), status: 'pending', date: today() };
  db.requests.push(r);
  commit();
  return [201, { request: r }];
}

/* PATCH /v1/contact-requests/{id} — {"status":"approved"|"declined"} (ТОЛЬКО школьник-владелец запроса) */
function answerRequestHandler(id, body, pr) {
  const r = db.requests.find((x) => x.id === id);
  if (!r) return [404, { error: 'запрос не найден' }];
  if (r.studentId !== pr.entityId) return [403, { error: 'чужой запрос: только школьник решает' }];
  if (body.status !== 'approved' && body.status !== 'declined') return [400, { error: 'status: approved | declined' }];
  r.status = body.status;
  commit();
  return [200, { ok: true }];
}

/* PATCH /v1/students/{id}/profile — сохранить резюме (ТОЛЬКО школьник на СВОЙ аккаунт) */
function profileHandler(sid, body, pr) {
  const s = studentOf(sid);
  if (!s) return [404, { error: 'школьник не найден' }];
  if (s.id !== pr.entityId) return [403, { error: 'чужой аккаунт: резюме меняет только владелец' }];
  const p = body.profile || {};
  s.profile = {
    headline: String(p.headline || ''),
    fame: String(p.fame || ''),
    about: String(p.about || ''),
    skills: Array.isArray(p.skills) ? p.skills.map(String) : [],
    projects: Array.isArray(p.projects) ? p.projects : (s.profile ? s.profile.projects : []),
  };
  commit();
  return [200, { ok: true, student: { id: s.id, profile: s.profile } }];
}

/* PATCH /v1/students/{id}/consent — {"field":"parent","value":true} (ТОЛЬКО школьник на СВОЙ аккаунт) */
function consentHandler(sid, body, pr) {
  const s = studentOf(sid);
  if (!s) return [404, { error: 'школьник не найден' }];
  if (s.id !== pr.entityId) return [403, { error: 'чужой аккаунт: согласие меняет только владелец' }];
  const { field, value } = body;
  if (!['parent', 'search', 'showName', 'portfolio'].includes(field)) {
    return [400, { error: 'field: parent | search | showName | portfolio' }];
  }
  /* in_search нельзя включить без parent_consent (правило доступа, BACKEND.md) */
  if (field === 'search' && value && !s.parent) return [400, { error: 'нельзя включить поиск без согласия родителя' }];
  s[field] = !!value;
  if (field === 'parent' && !s.parent) s.search = false;
  commit();
  return [200, { ok: true, student: { id: s.id, parent: s.parent, search: s.search, showName: s.showName, portfolio: s.portfolio } }];
}

/* POST /v1/register — создание аккаунта (роль + данные + логин/пароль).
   Возвращает токен: в демо пароль и есть токен; в БД — только SHA-256 хеш. */
function registerHandler(body) {
  const role = body.role;
  const name = String(body.name || '').trim();
  const login = String(body.login || '').trim().toLowerCase();
  const password = String(body.password || '').trim();
  if (!role || !name) return [400, { error: 'role и name обязательны' }];
  if (!login || password.length < 4) return [400, { error: 'login и password (от 4 символов) обязательны' }];
  if ((db.accounts || []).some((x) => x.login.toLowerCase() === login)) return [409, { error: 'логин уже занят' }];
  const mkAccount = (entityId) => ({ id: 'u' + (++db.seq), role, entityId, login, tokenHash: sha256(password) });
  if (role === 'student') {
    const s = {
      id: 's' + (++db.seq), name, grade: +body.grade || 9,
      city: String(body.city || ''), school: String(body.school || ''),
      direction: body.direction || 'IT',
      /* согласие родителя НЕ принимается из формы регистрации: несовершеннолетний
         не может сам себя согласовать (правило BACKEND.md). В демо его включает
         школьник тумблером «Согласие родителя» в кабинете (имитация SMS-кода). */
      parent: false, search: false, showName: false, portfolio: false,
      contact: `student${db.seq}.test@example.com`,
      profile: { headline: String(body.headline || ''), fame: '', about: '', skills: [], projects: [] },
    };
    db.students.push(s);
    db.accounts.push(mkAccount(s.id));
    commit();
    return [201, { role, token: password, account: { id: db.accounts[db.accounts.length - 1].id, role, entityId: s.id, name } }];
  }
  if (role === 'org') {
    const o = { id: 'o' + (++db.seq), name, city: String(body.city || ''), verified: false };
    db.orgs.push(o);
    db.keys[o.id] = genKeys(); /* у нового организатора своя пара ключей */
    db.accounts.push(mkAccount(o.id));
    commit();
    return [201, { role, token: password, account: { id: db.accounts[db.accounts.length - 1].id, role, entityId: o.id, name } }];
  }
  if (role === 'buyer') {
    const b = { id: 'b' + (++db.seq), name, type: body.type || 'Образовательное агентство' };
    db.buyers.push(b);
    db.accounts.push(mkAccount(b.id));
    commit();
    return [201, { role, token: password, account: { id: db.accounts[db.accounts.length - 1].id, role, entityId: b.id, name } }];
  }
  return [400, { error: 'role: student | org | buyer' }];
}

/* POST /v1/reset — вернуть сид-данные (кнопка «Сбросить демо-данные») */
function resetHandler() {
  db = seed();
  commit();
  return [200, { ok: true }];
}

/* ---------------- Роутер (RBAC) ----------------
   Публичные: health, stats, contests, orgs/{id}/public-key, certificates verify,
             login, accounts, portfolio (по правилам публичности), register, reset (демо).
   Приватные (нужен токен с нужной ролью): state (ролевой срез), me,
             contests POST (org), issue (org-владелец), talents (buyer),
             contact-requests POST (buyer) / PATCH (student-владелец),
             students/{id}/consent|profile (student-владелец).
   Неверный токен → 401. Недостаточно прав → 401. Чужая сущность → 403. */
async function handleApi(req, res, u, p) {
  const m = req.method;
  const seg = p.slice(4).split('/').filter(Boolean).map(decodeURIComponent);
  const body = (m === 'POST' || m === 'PATCH' || m === 'PUT') ? await readBody(req) : {};
  const pr = principalFromAuth(req);
  if (pr.__invalid) {
    /* токен передан, но недействителен — даже на публичных точках: вход просрочен */
    const t0 = Date.now();
    console.log(`[api] ${new Date().toISOString()} ${m} ${p} → 401 (неверный токен) (${Date.now() - t0}мс)`);
    return sendJson(res, 401, { error: 'неверный или просроченный токен' });
  }

  const t0 = Date.now();
  let status, data;
  const guard = (roles) => {
    const g = requireRole(pr, ...roles);
    return g ? [status = g[0], data = g[1]] : null;
  };
  if (m === 'GET' && seg[0] === 'health') {
    [status, data] = [200, { ok: true, name: 'proofy-api', time: new Date().toISOString() }];
  } else if (m === 'GET' && seg[0] === 'stats') {
    [status, data] = [200, publicStats()];
  } else if (m === 'GET' && seg[0] === 'state') {
    if ((data = guard(['student', 'org', 'buyer']))) { /* 401 */ }
    else [status, data] = roleState(pr);
  } else if (m === 'GET' && seg[0] === 'me') {
    [status, data] = meHandler(pr);
  } else if (m === 'POST' && seg[0] === 'reset') {
    [status, data] = resetHandler();
  } else if (m === 'GET' && seg[0] === 'certificates' && seg[2] === 'verify') {
    [status, data] = verifyHandler(seg[1], u.searchParams, pr);
  } else if (m === 'POST' && seg[0] === 'contests' && seg.length === 1) {
    if ((data = guard(['org']))) { /* 401 */ }
    else [status, data] = createContestHandler(body, pr);
  } else if (m === 'POST' && seg[0] === 'contests' && seg[2] === 'certificates') {
    if ((data = guard(['org']))) { /* 401 */ }
    else [status, data] = issueHandler(seg[1], body, pr);
  } else if (m === 'GET' && seg[0] === 'contests' && seg.length === 1) {
    [status, data] = contestsHandler(u.searchParams);
  } else if (m === 'GET' && seg[0] === 'contests' && seg.length === 2) {
    [status, data] = contestByIdHandler(seg[1]);
  } else if (m === 'GET' && seg[0] === 'hackathons') {
    [status, data] = hackathonsHandler();
  } else if (m === 'GET' && seg[0] === 'orgs' && seg[2] === 'public-key') {
    [status, data] = publicKeyHandler(seg[1]);
  } else if (m === 'GET' && seg[0] === 'talents') {
    if ((data = guard(['buyer', 'org']))) { /* 401 */ }
    else [status, data] = talentsHandler(u.searchParams, pr);
  } else if (m === 'POST' && seg[0] === 'contact-requests' && seg.length === 1) {
    if ((data = guard(['buyer', 'org']))) { /* 401 */ }
    else [status, data] = createRequestHandler(body, pr);
  } else if (m === 'PATCH' && seg[0] === 'contact-requests' && seg.length === 2) {
    if ((data = guard(['student']))) { /* 401 */ }
    else [status, data] = answerRequestHandler(seg[1], body, pr);
  } else if (m === 'PATCH' && seg[0] === 'students' && seg[2] === 'consent') {
    if ((data = guard(['student']))) { /* 401 */ }
    else [status, data] = consentHandler(seg[1], body, pr);
  } else if (m === 'PATCH' && seg[0] === 'students' && seg[2] === 'profile') {
    if ((data = guard(['student']))) { /* 401 */ }
    else [status, data] = profileHandler(seg[1], body, pr);
  } else if (m === 'POST' && seg[0] === 'login') {
    [status, data] = loginHandler(body);
  } else if (m === 'GET' && seg[0] === 'accounts') {
    [status, data] = accountsHandler();
  } else if (m === 'GET' && seg[0] === 'portfolio' && seg.length === 2) {
    [status, data] = portfolioHandler(seg[1], pr);
  } else if (m === 'POST' && seg[0] === 'register') {
    [status, data] = registerHandler(body);
  } else {
    [status, data] = [404, { error: 'not found', path: p }];
  }
  console.log(`[api] ${new Date().toISOString()} ${m} ${p} → ${status} (${Date.now() - t0}мс)`);
  sendJson(res, status, data);
}

/* ---------------- Статика (фронтенд) ---------------- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.map': 'application/json',
  '.csv': 'text/csv; charset=utf-8', '.webp': 'image/webp',
};
function serveStatic(res, p) {
  let file;
  try { file = decodeURIComponent(p); } catch (e) { file = p; }
  if (file === '/') file = '/index.html';
  const fp = path.normalize(path.join(ROOT, file));
  /* только строго внутри корня; server/ (база с закрытыми ключами) наружу не отдаём */
  if (fp !== ROOT && !fp.startsWith(ROOT + path.sep)) { res.writeHead(403, { 'Content-Type': 'text/plain' }); return res.end('forbidden'); }
  if (fp === path.join(ROOT, 'server') || fp.startsWith(path.join(ROOT, 'server') + path.sep)) { res.writeHead(403, { 'Content-Type': 'text/plain' }); return res.end('forbidden'); }
  fs.stat(fp, (err, st) => {
    if (!err && st.isDirectory()) fs.readFile(path.join(fp, 'index.html'), (e2, b) => {
      if (e2) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('404 not found'); }
      res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-store' }); res.end(b);
    });
    else fs.readFile(fp, (e2, b) => {
      if (e2) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('404 not found'); }
      const ext = path.extname(fp).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(b);
    });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (p === '/v1' || p.startsWith('/v1/')) return await handleApi(req, res, u, p);
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'method not allowed' });
    return serveStatic(res, p);
  } catch (e) {
    console.error('[error]', e.message);
    if (!res.headersSent) sendJson(res, 500, { error: e.message || 'internal error' });
    else res.end();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Proofy API + сайт: http://localhost:${PORT}  (данные: ${path.relative(ROOT, require('./db').DATA_FILE)})`);
  console.log(`Сертификатов в реестре: ${db.certs.length}, конкурсов: ${db.contests.length}`);
});

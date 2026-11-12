'use strict';
/* =====================================================================
   Proofy — СТРОГИЕ тесты (RBAC-модель).
   1) Модульные: weight (все ветки формулы и границы 0/100), crypto
      (формат подписи, kid, подмена каждого поля, чужой ключ, мусор),
      db (сид-данные, сид-сертификация, аккаунты, save/load).
   2) Интеграционные: точные формы ответов, точные значения веса/баллов
      для всех 12 сид-сертификатов, RBAC (401/403, только СВОЙ кабинет),
      жизненный цикл запросов, регистрация с логином, приватность резюме,
      безопасность статики, персистентность, детерминизм reset,
      кросс-проверка подписей WebCrypto «как в браузере».
   Запуск: node server/test.strict.js
   ===================================================================== */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const nodeCrypto = require('node:crypto');

/* Изолированная БД ДО require модулей */
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'proofy-strict-'));
const UNIT_DB = path.join(TMP, 'unit-db.json');
const LIVE_DB = path.join(TMP, 'live-db.json');
process.env.PROOFY_DATA_FILE = UNIT_DB;

const PORT = 4299;
const BASE = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => nodeCrypto.createHash('sha256').update(s).digest('hex');

let passed = 0, failed = 0;
const fail = (name, extra) => { failed++; console.error(`  ✗ ${name}${extra ? ' — ' + extra : ''}`); };
const pass = (name) => { passed++; console.log(`  ✓ ${name}`); };
const check = (cond, name, extra) => (cond ? pass(name) : fail(name, extra));
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const keySet = (o) => Object.keys(o).sort();
const section = (t) => console.log('\n' + t);

/* ---------------- HTTP-хелперы ---------------- */
function rawReq(method, p, { body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1', port: PORT, path: p, method,
      agent: false,
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
    }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', reject);
    if (data !== null) req.write(data);
    req.end();
  });
}
async function j(method, p, body, headers) {
  const r = await rawReq(method, p, { body, headers });
  let data = null;
  try { data = JSON.parse(r.body); } catch (e) { /* не JSON */ }
  return { status: r.status, data, headers: r.headers, body: r.body };
}
let srv, srvOut = '';
function startServer() {
  srvOut = '';
  srv = spawn(process.execPath, ['--trace-uncaught', path.join(__dirname, 'server.js')], {
    env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1', PROOFY_DATA_FILE: LIVE_DB },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  srv.stdout.on('data', (d) => { srvOut += d; });
  srv.stderr.on('data', (d) => { srvOut += d; });
  srv.on('exit', (code, sig) => { console.error(`\n[spawn] СЕРВЕР УШЁЛ: exitCode=${code} signal=${sig} pid=${srv.pid}`); });
}
async function waitUp() {
  for (let i = 0; i < 80; i++) {
    try { const r = await fetch(BASE + '/v1/health'); if (r.ok) { await r.arrayBuffer(); return true; } await r.arrayBuffer(); } catch (e) { /* стартует */ }
    await sleep(150);
  }
  return false;
}
function stopServer() {
  return new Promise((res) => {
    if (!srv) return res();
    const to = setTimeout(res, 3000);
    srv.once('exit', () => { clearTimeout(to); res(); });
    srv.kill('SIGTERM');
  });
}

/* Ожидаемые значения (независимо пересчитаны по формуле BACKEND.md):
   k1: 55 + log10(300)*5→12 + 10 = 77
   k2: 55 + log10(1200)*5→15 + 10 = 80
   k3: 75 + 15(кап) + 10 = 100 (обрезка по верху)
   k4: 85 + 15(кап) −30 −25 −20 = 25
   k5: 55 + log10(160)*5→11 + 10 = 76 */
const WEIGHTS = { k1: 77, k2: 80, k3: 100, k4: 25, k5: 76 };
/* Все 12 сид-сертификатов: [id, contestId, studentId, result, баллы] */
const EXPECTED_CERTS = [
  ['PRF-GH26-0001', 'k1', 's1', 'winner', 77],
  ['PRF-RI26-0001', 'k3', 's1', 'prize', 70],
  ['PRF-GH26-0002', 'k1', 's2', 'prize', 54],
  ['PRF-FT26-0001', 'k5', 's2', 'winner', 76],
  ['PRF-OM26-0001', 'k2', 's3', 'winner', 80],
  ['PRF-SO26-0001', 'k4', 's3', 'winner', 25],
  ['PRF-OM26-0002', 'k2', 's4', 'prize', 56],
  ['PRF-RI26-0002', 'k3', 's4', 'winner', 100],
  ['PRF-FT26-0002', 'k5', 's5', 'prize', 53],
  ['PRF-GH26-0003', 'k1', 's5', 'participant', 12],
  ['PRF-SO26-0002', 'k4', 's6', 'winner', 25],
  ['PRF-OM26-0003', 'k2', 's6', 'participant', 12],
];
const DISPLAY = { s1: 'А. Н.', s2: 'Данияр Сапаров', s3: 'М. Е.', s4: 'Т. А.', s5: 'Аружан Кайратова', s6: 'Е. Б.' };
/* Демо-логины (пароль = токен) */
const H = {
  s1: { token: 'pfy_demo_s1', h: { Authorization: 'Bearer pfy_demo_s1' } },
  s3: { token: 'pfy_demo_s3', h: { Authorization: 'Bearer pfy_demo_s3' } },
  s4: { token: 'pfy_demo_s4', h: { Authorization: 'Bearer pfy_demo_s4' } },
  s5: { token: 'pfy_demo_s5', h: { Authorization: 'Bearer pfy_demo_s5' } },
  o1: { token: 'pfy_demo_o1', h: { Authorization: 'Bearer pfy_demo_o1' } },
  o2: { token: 'pfy_demo_o2', h: { Authorization: 'Bearer pfy_demo_o2' } },
  b1: { token: 'pfy_demo_b1', h: { Authorization: 'Bearer pfy_demo_b1' } },
};

/* ================= МОДУЛЬНЫЕ ================= */
async function unitTests() {
  const W = require('./weight');
  const C = require('./crypto');
  const DB = require('./db');
  const b64uRe = /^[A-Za-z0-9_-]+$/;

  section('[weight] формула и границы');
  const w = (over = {}, org = { verified: true }) =>
    W.contestWeight({ level: 'city', participants: 100, selection: false, paid: false, awarded: 0, ...over }, org);
  check(w({}).total === 45 && w({}).parts.length === 2, 'база city + 100 уч. = 45 (2 части)');
  check(w({ level: 'school', participants: 10 }).total === 25, 'school + 10 уч. = 25 (log10=1→5)');
  check(w({ participants: 1 }).total === 35, '1 участник → +0');
  check(w({ participants: 10000 }).total === 50, 'кап размера: 10000 уч. → +15');
  check(w({ selection: true }).total === 55, 'отбор → +10');
  check(w({ paid: true }).total === 20, 'платно без отбора → −25');
  check(w({ paid: true, selection: true }).total === 55, 'платно С отбором → без штрафа');
  check(w({}, { verified: false }).total === 15, 'неподтверждённый организатор → −30');
  check(w({ orgVerified: true }, { verified: false }).total === 45, 'override orgVerified=true игнорирует неподтверждённый org');
  check(w({ awarded: 50 }).total === 45, 'награждено ровно 50% → без штрафа');
  check(w({ awarded: 51 }).total === 25, 'награждено 51% → −20');
  check(w({ level: 'school', participants: 10, paid: true, awarded: 100 }, { verified: false }).total === 0, 'обрезка вниз до 0 (25−50 → 0)');
  check(w({ level: 'national', participants: 2500, selection: true }).total === 100, 'обрезка вверх до 100');
  check(W.certPoints(77, 'prize') === 54, 'баллы: 77×0.7 → 54');
  check(W.certPoints(25, 'participant') === 4, 'баллы: 25×0.15 → 4');
  check(W.certPoints(77, 'unknown') === 12, 'неизвестный результат → коэффициент участника');
  check(eq(W.LEVELS, { school: { label: 'Школьный', base: 20 }, city: { label: 'Городской', base: 35 }, region: { label: 'Областной', base: 55 }, national: { label: 'Республиканский', base: 75 }, intl: { label: 'Международный', base: 85 } }), 'таблица уровней точная');

  section('[crypto] ECDSA P-256 / P1363 / base64url');
  const ks = C.genKeys(), ks2 = C.genKeys();
  check(ks.pub.kty === 'EC' && ks.pub.crv === 'P-256' && !!ks.pub.x && !!ks.pub.y, 'JWK: kty=EC, crv=P-256, x/y');
  check(b64uRe.test(ks.pub.x) && b64uRe.test(ks.pub.y), 'JWK x/y в base64url (без +/=)');
  check(ks.kid === sha256(ks.pub.x + ks.pub.y).slice(0, 16), 'kid = SHA-256(x+y)[0:16]');
  const payload = C.certPayload({ id: 'PRF-X9-0001', studentId: 's1', result: 'winner' }, { orgId: 'o1', name: 'Тест', date: '2026-01-01' }, 'winner');
  check(payload === 'PROOFY/1|PRF-X9-0001|o1|Тест|2026-01-01|s1|winner', 'строка подписи — точный формат BACKEND.md');
  const sig = C.sign(ks, payload);
  check(Buffer.from(sig, 'base64url').length === 64, 'подпись IEEE P1363: ровно 64 байта (r‖s)');
  check(b64uRe.test(sig), 'подпись в base64url без «=»');
  check(C.verify(ks, payload, sig) === true, 'своя подпись верна');
  check(C.verify(ks, payload + 'x', sig) === false, 'подмена строки → false');
  check(C.verify(ks2, payload, sig) === false, 'чужой ключ → false');
  check(C.verify(ks, payload, 'AAAA') === false, 'мусорная подпись → false (не бросает исключение)');
  check(C.verify(ks, payload, sig + 'AA') === false, 'подпись 66 байт → false');

  section('[db] сид-данные и хранилище');
  const s = DB.seed();
  check(s.orgs.length === 4 && s.contests.length === 5 && s.students.length === 6 && s.certs.length === 12 && s.buyers.length === 2 && s.requests.length === 2, 'сид: 4/5/6/12/2/2');
  check(eq(EXPECTED_CERTS.map((c) => c[0]).sort(), s.certs.map((c) => c.id).sort()), 'сид: 12 точных ID сертификатов');
  check(!s.certs.some((c) => c.id === 'PRF-GH26-0999'), 'сид: PRF-GH26-0999 отсутствует (подделка из питча)');
  check(s.certs.every((c) => c.sig && b64uRe.test(c.sig) && Buffer.from(c.sig, 'base64url').length === 64 && /^[0-9a-f]{16}$/.test(c.kid)), 'сид: все сертификаты подписаны (64 байта, kid 16 hex)');
  check(s.certs.every((c) => C.verifyCertSig({ contests: s.contests, keys: s.keys, certs: s.certs }, c)), 'сид: каждая подпись проходит проверку');
  check(s.orgs.every((o) => s.keys[o.id] && s.keys[o.id].pub && s.keys[o.id].priv), 'сид: у каждого организатора пара ключей');
  check(s.accounts.length === 12 && s.accounts.every((a) => a.tokenHash === sha256(DB.DEMO_ACCOUNTS.find((d) => d.login === a.login).pass)), 'accounts: 12 аккаунтов, в БД только SHA-256 хеши паролей');
  check(s.students[0].profile && s.students[0].profile.headline.length > 0, 'students: резюме сид-школьника заполнено');
  check(s.seq === 100 && s.checks === 0 && !('session' in s), 'seq/checks сид, сессий в БД нет (вход по токенам)');
  DB.save(s);
  check(eq(DB.load(), s), 'save/load: round-trip без потерь');
}

/* ================= ИНТЕГРАЦИОННЫЕ ================= */
async function integrationTests() {
  process.env.PROOFY_DATA_FILE = LIVE_DB;
  startServer();
  if (!(await waitUp())) { console.error('Сервер не запустился:\n' + srvOut); process.exit(1); }

  section('[verify] точная форма ответа 200');
  const v = await j('GET', '/v1/certificates/PRF-GH26-0001/verify');
  check(v.status === 200, 'статус 200');
  check(eq(keySet(v.data), ['cert', 'claimSigOk', 'claimed_result_sig_ok', 'contest', 'found', 'holder', 'intact', 'org', 'points', 'sigOk', 'sig_ok']), 'полный набор полей уровня 200');
  check(eq(keySet(v.data.cert), ['contestId', 'contest_id', 'id', 'issued_at', 'key_id', 'kid', 'result', 'sig', 'signature', 'studentId', 'student_id']), 'полный набор полей cert');
  check(eq(keySet(v.data.holder), ['city', 'contact', 'display_name', 'grade', 'initials', 'name', 'show_name']), 'полный набор полей holder (имя только при show_name)');
  check(v.data.holder.name === null && v.data.holder.contact === null, 's1 (show_name=false): имя и контакт в verify не отдаются');
  check(eq(keySet(v.data.org), ['id', 'name', 'verified']), 'полный набор полей org');
  check(eq(keySet(v.data.contest), ['awarded', 'date', 'direction', 'id', 'level', 'name', 'paid', 'participants', 'selection', 'weight', 'weight_parts']), 'полный набор полей contest');
  check(v.data.cert.sig && v.data.cert.sig === v.data.cert.signature && v.data.cert.kid === v.data.cert.key_id, 'sig/signature и kid/key_id — одна и та же ценность');
  check(v.headers['content-type'].startsWith('application/json'), 'Content-Type: application/json');
  check(v.headers['access-control-allow-origin'] === '*', 'CORS: Access-Control-Allow-Origin: *');

  section('[verify] 12 сид-сертификатов: вес, баллы, владелец, подпись');
  for (const [id, cid, sid, result, points] of EXPECTED_CERTS) {
    const r = (await j('GET', `/v1/certificates/${id}/verify`)).data;
    const okAll = r.found === true
      && r.contest.id === cid && r.cert.studentId === sid && r.cert.result === result
      && r.contest.weight === WEIGHTS[cid]
      && r.points === points
      && r.sigOk === true && r.claimSigOk === null && r.intact === true
      && r.holder.display_name === DISPLAY[sid] && r.holder.grade && typeof r.holder.city === 'string'
      && r.org.verified === (cid === 'k4' ? false : true)
      && Array.isArray(r.contest.weight_parts);
    check(!!okAll, `${id}: ${cid}/${sid}/${result} → вес ${WEIGHTS[cid]}, баллы ${points}, «${DISPLAY[sid]}»`, JSON.stringify(r));
  }
  const parts = (await j('GET', '/v1/certificates/PRF-GH26-0001/verify')).data.contest.weight_parts;
  check(eq(parts, [['Уровень: областной', 55], ['300 участников', 12], ['Есть отборочный этап', 10]]), 'weight_parts — точные пары [название, значение]');

  section('[verify] 404 и claimed_result');
  const nf = await j('GET', '/v1/certificates/PRF-GH26-0999/verify');
  check(nf.status === 404 && eq(nf.data, { found: false }), 'выдуманный ID → 404, тело ровно {found:false}');
  const vLower = await j('GET', '/v1/certificates/prf-gh26-0001/verify');
  check(vLower.status === 200 && vLower.data.found === true, 'ID без учёта регистра');
  const cSame = (await j('GET', '/v1/certificates/PRF-GH26-0001/verify?claimed_result=winner')).data;
  check(cSame.claimSigOk === null, 'claim === результат → claimSigOk=null (не сверяли)');
  const cDiff = (await j('GET', '/v1/certificates/PRF-OM26-0003/verify?claimed_result=winner')).data;
  check(cDiff.sigOk === true && cDiff.claimSigOk === false, 'подделка результата: настоящая верна, «winner» не сходится');
  const cClaim = (await j('GET', '/v1/certificates/PRF-GH26-0001/verify?claimed_result=participant')).data;
  check(cClaim.sigOk === true && cClaim.claimSigOk === false, 'claim (participant) против winner в реестре → false');

  section('[rbac] вход и роли: 401/403, только СВОЙ кабинет');
  check((await j('GET', '/v1/state')).status === 401, 'state аноним → 401');
  check((await j('GET', '/v1/talents')).status === 401, 'talents аноним → 401');
  check((await j('POST', '/v1/contests', { name: 'X' })).status === 401, 'contests POST аноним → 401');
  check((await j('GET', '/v1/state', null, { Authorization: 'Bearer wrong-token' })).status === 401, 'неверный токен → 401 (даже на /v1/state)');
  check((await j('GET', '/v1/health', null, { Authorization: 'Bearer wrong-token' })).status === 401, 'неверный токен → 401 даже на публичной точке (вход просрочен)');
  const lg = await j('POST', '/v1/login', { login: 'aigerim', password: 'pfy_demo_s1' });
  check(lg.status === 200 && lg.data.token === H.s1.token && lg.data.account.role === 'student' && lg.data.account.entityId === 's1', 'login: токен + роль + сущность');
  check((await j('POST', '/v1/login', { login: 'aigerim', password: 'wrong' })).status === 401, 'login: неверный пароль → 401');
  check((await j('POST', '/v1/login', { login: 'nope', password: 'x' })).status === 401, 'login: неизвестный логин → 401');
  const me = (await j('GET', '/v1/me', null, H.s1.h)).data;
  check(me.role === 'student' && me.entityId === 's1' && me.name === 'Айгерим Нурланова', 'me: кто я по токену');
  /* ролевой срез — только свои данные */
  const stS = (await j('GET', '/v1/state', null, H.s1.h)).data;
  check(eq(stS.students.map((x) => x.id), ['s1']) && stS.certs.length === 2 && stS.contests.length === 5 && stS.orgs.length >= 4 && stS.buyers.length === 2 && stS.requests.length === 1, 'student s1: свой кабинет — 1 студент, 2 сертификата, КАТАЛОГ (5 конкурсов, все орги, все вузы), 1 запрос');
  const stO = (await j('GET', '/v1/state', null, H.o1.h)).data;
  check(eq(stO.orgs.map((o) => o.id), ['o1']) && eq(stO.contests.map((k) => k.id), ['k1']) && stO.certs.length === 3 && stO.buyers.length === 2 && stO.requests.length === 0, 'org o1: только свои конкурсы и сертификаты (3) + каталог вузов (2)');
  check(stS.contests.every((k) => k.weight != null && k.org && k.org.id), 'каталог школьника: конкурсы с весом и организацией');
  const stB = (await j('GET', '/v1/state', null, H.b1.h)).data;
  check(eq(stB.buyers.map((b) => b.id), ['b1']) && stB.requests.length === 1 && stB.certs.length === 0 && stB.contests.length === 0, 'buyer b1: только свои запросы, без реестра сертификатов');
  /* школа не видит реестр покупателей; студент не трогает чужие данные */
  check((await j('GET', '/v1/talents', null, H.s1.h)).status === 401, 'student не ищет таланты → 401');
  check((await j('POST', '/v1/contests', { name: 'Чужой' }, H.s1.h)).status === 401, 'student не создаёт конкурсы → 401');
  check((await j('PATCH', '/v1/students/s2/consent', { field: 'parent', value: true }, H.s1.h)).status === 403, 'student чужое согласие → 403');
  check((await j('PATCH', '/v1/students/s1/profile', { profile: { headline: 'x' }, } , H.s3.h)).status === 403, 'чужое резюме → 403');

  section('[talents] приватность и точность поиска (buyer)');
  const t = (await j('GET', '/v1/talents', null, H.b1.h)).data;
  check(eq(t.talents.map((x) => x.id), ['s1', 's2', 's3', 's5', 's6']), 'только parent_consent AND in_search, сортировка по баллам');
  check(t.hidden_count === 1, 'hidden_count = 1 (Тимур без согласия)');
  check(t.talents.find((x) => x.id === 's1').display_name === 'А. Н.' && t.talents.find((x) => x.id === 's2').display_name === 'Данияр Сапаров', 'имя — только у show_name, остальные инициалы');
  check(t.talents.every((x) => x.contact === undefined && x.profile === undefined), 'поиск не отдаёт контакты и резюме (только через portfolio)');

  section('[contests] создание (org из токена) и рейтинг');
  const cc = await j('POST', '/v1/contests', { name: 'Городская олимпиада по физике', level: 'city', direction: 'Физика', participants: 100, awarded: 15, date: '2026-11-14', selection: true, paid: false, orgId: 'o2' }, H.o1.h);
  check(cc.status === 201 && cc.data.contest.name === 'Городская олимпиада по физике' && cc.data.contest.next === 1 && cc.data.contest.orgId === 'o1', 'создание: 201, орг = владелец токена (orgId из тела игнорируется)');
  check((await j('POST', '/v1/contests', { name: '   ' }, H.o1.h)).status === 400, 'пустое название → 400');
  check((await j('POST', '/v1/contests', { name: 'X', level: 'galactic' }, H.o1.h)).data.contest.level === 'city', 'невалидный уровень → default city');
  check((await j('POST', '/v1/contests', { name: 'X' }, H.b1.h)).status === 401, 'buyer не создаёт конкурсы → 401');
  const rk = (await j('GET', '/v1/contests')).data.contests;
  check(eq(rk.map((x) => x.weight), [100, 80, 77, 76, 55, 35, 25]), 'рейтинг (публичный): сортировка по весу, значения точные');
  check(eq(rk[0].id, 'k3') && rk[0].weight_parts.length === 3, 'первое место k3 (100), части веса');
  const rkPh = (await j('GET', '/v1/contests?direction=' + encodeURIComponent('Физика'))).data.contests;
  check(rkPh.length === 1 && rkPh[0].id === cc.data.contest.id && rkPh[0].weight === 55, 'фильтр по направлению, вес 55 (35+10+10)');

  section('[issue] выдача только в СВОЙ конкурс');
  check((await j('POST', '/v1/contests/k3/certificates', { rows: [{ name: 'Тест Тестов', grade: 9, city: 'Актобе', school: 'СОШ №1', result: 'winner' }] }, H.o1.h)).status === 403, 'org o1 → чужой конкурс k3 → 403');
  check((await j('POST', '/v1/contests/k1/certificates', { rows: [] }, H.o1.h)).status === 400, 'пустой список → 400');
  const badRows = await j('POST', '/v1/contests/k1/certificates', { rows: [{ name: 'А', grade: 9, city: 'А', school: 'С', result: 'winner' }, { name: 'Б', grade: 99, city: 'А', school: 'С', result: 'winner' }] }, H.o1.h);
  check(badRows.status === 400 && (await j('GET', '/v1/certificates/PRF-GH26-0004/verify')).status === 404, 'атомарность: ошибка во 2-й строке → ничего не создано');
  const is1 = await j('POST', '/v1/contests/k1/certificates', { rows: [{ name: 'Наталья Шестакова', grade: 10, city: 'Актобе', school: 'СОШ №7', result: 'winner' }] }, H.o1.h);
  check(is1.status === 201 && eq(is1.data.issued, ['PRF-GH26-0004']), 'выдача нового: 201, ID PRF-GH26-0004 (next=4)');
  const vNew = (await j('GET', '/v1/certificates/PRF-GH26-0004/verify')).data;
  check(vNew.found === true && vNew.sigOk === true && vNew.points === 77 && vNew.holder.display_name === 'Н. Ш.', 'выданный сертификат: проверен, 77 баллов, инициалы');
  const is2 = await j('POST', '/v1/contests/k1/certificates', { rows: [{ name: 'Айгерим Нурланова', grade: 10, city: 'Хромтау', school: 'Школа-гимназия №1', result: 'prize' }] }, H.o1.h);
  check(is2.status === 201 && eq(is2.data.issued, ['PRF-GH26-0005']), 'выдача существующему: следующий ID, без дубля');
  const vNew2 = (await j('GET', '/v1/certificates/PRF-GH26-0005/verify')).data;
  check(vNew2.cert.studentId === 's1' && vNew2.holder.display_name === 'А. Н.', 'выдача существующему: тот же holder');
  check((await j('POST', '/v1/contests/k1/certificates', { rows: [{ name: 'X', grade: 9, city: 'А', school: 'С', result: 'winner' }] }, H.s1.h)).status === 401, 'student не выдаёт сертификаты → 401');

  section('[consent] правила доступа (свой аккаунт)');
  check((await j('PATCH', '/v1/students/s4/consent', { field: 'search', value: true }, H.s4.h)).status === 400, 'search без parent_consent → 400');
  check((await j('PATCH', '/v1/students/s4/consent', { field: 'hacker', value: true }, H.s4.h)).status === 400, 'неизвестное поле → 400');
  await j('PATCH', '/v1/students/s4/consent', { field: 'parent', value: true }, H.s4.h);
  const c1 = await j('PATCH', '/v1/students/s4/consent', { field: 'search', value: true }, H.s4.h);
  check(c1.status === 200 && c1.data.student.search === true, 'search после согласия родителя');
  const c2 = await j('PATCH', '/v1/students/s4/consent', { field: 'parent', value: false }, H.s4.h);
  check(c2.data.student.search === false, 'отключение согласия родителя принудительно выключает search');
  check((await j('PATCH', '/v1/students/nope/consent', { field: 'parent', value: true }, H.s4.h)).status === 404, 'неизвестный школьник → 404');

  section('[contact-requests] жизненный цикл (buyer + student)');
  check((await j('POST', '/v1/contact-requests', { studentId: 'nope', purpose: 'x' }, H.b1.h)).status === 404, 'неизвестный школьник → 404');
  check((await j('POST', '/v1/contact-requests', { studentId: 's4', purpose: 'x' }, H.b1.h)).status === 403, 'школьник без согласия → 403');
  const cr = (await j('POST', '/v1/contact-requests', { studentId: 's3', purpose: 'Грант на обучение' }, H.b1.h)).data;
  check(cr.request.status === 'pending' && cr.request.buyerId === 'b1', 'создан pending от покупателя токена b1');
  check((await j('GET', '/v1/talents', null, H.b1.h)).data.talents.find((x) => x.id === 's3').contact_open === false, 'pending → контакт ещё закрыт');
  check((await j('PATCH', `/v1/contact-requests/${cr.request.id}`, { status: 'approved' }, H.b1.h)).status === 401, 'buyer не отвечает на запросы → 401');
  check((await j('PATCH', '/v1/contact-requests/r1', { status: 'approved' }, H.s3.h)).status === 403, 'чужой запрос (r1 у s1) → 403');
  check((await j('PATCH', `/v1/contact-requests/${cr.request.id}`, { status: 'approved' }, H.s3.h)).status === 200, 'одобрение школьником-владельцем');
  check((await j('GET', '/v1/talents', null, H.b1.h)).data.talents.find((x) => x.id === 's3').contact_open === true, 'approved → contact_open=true у s3');
  const cr2 = (await j('POST', '/v1/contact-requests', { studentId: 's5', purpose: 'Стажировка' }, H.b1.h)).data;
  check((await j('PATCH', `/v1/contact-requests/${cr2.request.id}`, { status: 'declined' }, H.s5.h)).status === 200, 'отклонение');
  check((await j('PATCH', `/v1/contact-requests/${cr2.request.id}`, { status: 'weird' }, H.s5.h)).status === 400, 'невалидный статус → 400');
  check((await j('PATCH', '/v1/contact-requests/nope', { status: 'approved' }, H.s5.h)).status === 404, 'неизвестный запрос → 404');
  check((await j('POST', '/v1/contact-requests', { studentId: 's3', purpose: 'x' }, { Authorization: 'Bearer wrong' })).status === 401, 'неверный токен → 401');

  section('[portfolio] правила публичности и контакта');
  const pf1 = await j('GET', '/v1/portfolio/s1');
  check(pf1.status === 200 && pf1.data.student.name === null && pf1.data.contact === null, 'аноним: публичное портфолио s1 — без полного имени и контакта');
  check(pf1.data.student.display_name.startsWith('Школьник, 10 класс'), 'аноним: имя скрыто до показа (показан класс)');
  check((await j('GET', '/v1/portfolio/s4')).status === 403, 's4: portfolio выключен, в поиске тоже нет → 403');
  const pf3 = (await j('GET', '/v1/portfolio/s3', null, H.b1.h)).data;
  check(pf3.student.name === 'Мадина Ержанова' && pf3.contact === 'madina.test@example.com', 'buyer b1 + approved: имя и контакт открыты');
  check(pf3.request.status === 'approved', 'в resume виден статус запроса покупателя');
  const pf3anon = await j('GET', '/v1/portfolio/s3');
  check(pf3anon.status === 403, 'аноним: s3 (portfolio выключено, не в поиске) → 403, контакта нет');

  section('[register] аккаунт = логин + пароль, сразу в СВОЙ кабинет');
  const regOrg = (await j('POST', '/v1/register', { role: 'org', name: 'Новый орг (тест)', city: 'Актобе', login: 'new_org', password: 'pw_org_1' }));
  check(regOrg.status === 201 && regOrg.data.token === 'pw_org_1' && regOrg.data.account.role === 'org', 'регистрация org → 201 + токен', JSON.stringify(regOrg.data));
  const newOrgId = regOrg.data.account.entityId;
  check((await j('GET', `/v1/orgs/${newOrgId}/public-key`)).status === 200, 'у нового org есть пара ключей (public-key 200)');
  const regStu = (await j('POST', '/v1/register', { role: 'student', name: 'Свежий Студент', grade: 11, city: 'Актобе', school: 'СОШ №1', direction: 'IT', parent: true, headline: 'Пишу на Go', login: 'fresh_stu', password: 'pw_stu_1' })).data;
  check(regStu.token === 'pw_stu_1', 'регистрация student → токен');
  const freshState = (await j('GET', '/v1/state', null, { Authorization: 'Bearer ' + regStu.token })).data;
  check(eq(freshState.students.map((x) => x.id), [regStu.account.entityId]) && freshState.certs.length === 0, 'новый student: в своём кабинете только он сам и 0 сертификатов');
  check(!(await j('GET', '/v1/talents', null, H.b1.h)).data.talents.some((x) => x.id === regStu.account.entityId), 'новый student: скрыт в поиске (search=false)');
  const regBuy = (await j('POST', '/v1/register', { role: 'buyer', name: 'Свежий Бьюер', type: 'Вуз', login: 'fresh_buy', password: 'pw_buy_1' })).data;
  check(!!regBuy.account.entityId, 'регистрация buyer');
  check((await j('POST', '/v1/register', { role: 'alien', name: 'X', login: 'a1', password: 'pw11' })).status === 400, 'неизвестная роль → 400');
  check((await j('POST', '/v1/register', { role: 'buyer', login: 'a2', password: 'pw11' })).status === 400, 'без имени → 400');
  check((await j('POST', '/v1/register', { role: 'buyer', name: 'Y', login: 'a3' })).status === 400, 'без пароля → 400');
  check((await j('POST', '/v1/register', { role: 'buyer', name: 'Z', login: 'new_org', password: 'pw22' })).status === 409, 'повторный логин → 409');

  section('[security] статика и утечки');
  const forbidden = async (p, name) => {
    const r = await rawReq('GET', p);
    check(r.status !== 200 && !r.body.includes('"orgs"') && !r.body.includes('"d":"'), `${name} → ${r.status} (контент не отдаётся)`);
  };
  await forbidden('/server/data/db.json', 'базу с закрытыми ключами');
  await forbidden('/server/server.js', 'исходный код сервера');
  await forbidden('/server/', 'директорию /server/');
  await forbidden('/..%2fserver%2fdata%2fdb.json', 'path traversal %2f');
  await forbidden('/%2e%2e/server/data/db.json', 'path traversal %2e%2e');
  const home = await rawReq('GET', '/');
  check(home.status === 200 && home.body.includes('<!doctype html'), 'GET / → index.html');
  check(!home.body.includes('href="#/org"') && !home.body.includes('href="#/student"') && !home.body.includes('href="#/buyer"'), 'index.html: прямых ссылок на кабинеты в шапке/таббаре нет');
  const appjs = await rawReq('GET', '/app.js');
  check(appjs.status === 200 && appjs.body.includes('ensureBackend'), 'GET /app.js → фронт с подключением к API');
  check((await rawReq('GET', '/nope')).status === 404, 'несуществующий файл → 404');
  const opt = await rawReq('OPTIONS', '/v1/health');
  check(opt.status === 204 && opt.headers['access-control-allow-methods'].includes('PATCH'), 'OPTIONS → 204 + CORS-методы');
  check((await rawReq('POST', '/index.html', { body: '{}' })).status === 405, 'POST к статику → 405');
  const v1root = await j('GET', '/v1');
  check(v1root.status === 404 && typeof v1root.data === 'object', 'GET /v1 → 404 JSON');
  const stateBody = (await rawReq('GET', '/v1/state')).body;
  check(stateBody.includes('требуется вход') && !stateBody.includes('pfy_demo_b1') && !/"d":"[^"]+"/.test(stateBody), 'state аноним: 401-сообщение, без паролей и приватных полей JWK');
  const pk = (await j('GET', '/v1/orgs/o1/public-key')).data;
  check(pk.jwk.kty === 'EC' && pk.jwk.crv === 'P-256' && pk.jwk.d === undefined && pk.jwk.dp === undefined && /^[0-9a-f]{16}$/.test(pk.kid), 'public-key: только открытые поля JWK');
  check((await j('GET', '/v1/orgs/nope/public-key')).status === 404, 'public-key: неизвестный org → 404');

  section('[webcrypto] кросс-проверка «сервер → браузер»');
  const subtle = globalThis.crypto.subtle;
  const st = (await j('GET', '/v1/state', null, H.s3.h)).data;
  const wcVerify = async (jwk, sigB64u, payload) => {
    const key = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const sig = new Uint8Array(Buffer.from(sigB64u, 'base64url'));
    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, new TextEncoder().encode(payload));
  };
  for (const [cid, oid, other] of [['k2', 'o2', 'o1'], ['k4', 'o4', 'o1']]) {
    const c = st.certs.find((x) => x.contestId === cid);
    const k = st.contests.find((x) => x.id === cid);
    const pl = `PROOFY/1|${c.id}|${k.orgId}|${k.name}|${k.date}|${c.studentId}|${c.result}`;
    const okReal = await wcVerify(st.keys[oid].pub, c.sig, pl);
    const okFake = await wcVerify(st.keys[oid].pub, c.sig, pl.replace(`|${c.result}`, '|prize'));
    const okOther = await wcVerify(st.keys[other].pub, c.sig, pl);
    check(okReal && !okFake && !okOther, `WebCrypto: ${c.id} — настоящая верна, подмена/чужой ключ отклонены`);
  }

  section('[catalog] каталоги: школьник видит оргов/вузов, орг ищет талантов');
  /* публичный каталог хакатонов */
  let h = await j('GET', '/v1/hackathons');
  /* 4 сид-соревнования с отбором + 1, созданный в секции «конкурсы» */
  check(h.status === 200 && h.data.hackathons.length === 5 && h.data.hackathons.every((x) => x.weight && x.org) && h.data.hackathons.some((x) => x.id === 'k1'), 'GET /v1/hackathons: только отбор, вес + орг, Gambit на месте');
  check((await j('GET', '/v1/contests/k1')).data.contest.name === 'Gambit Hackathon 2026', 'GET /v1/contests/k1: деталь');
  check((await j('GET', '/v1/contests/k999')).status === 404, 'GET /v1/contests/k999 → 404');
  /* организатор ищет таланты (раньше только покупатель) */
  let tg = await j('GET', '/v1/talents?min_weight=70', null, H.o1.h);
  check(tg.status === 200 && Array.isArray(tg.data.talents), 'org ищет таланты → 200');
  check(tg.data.talents.every((x) => !x.name && x.display_name), 'org-поиск: полные имена не раскрываются');
  /* org отправляет запрос контакта; buyerId в запросе = id орг-а */
  let rq = await j('POST', '/v1/contact-requests', { studentId: 's3', purpose: 'Приглашение на хакатон' }, H.o1.h);
  check(rq.status === 201 && rq.data.request.buyerId === 'o1', 'org: запрос контакта (buyerId = id орг-а)');
  /* школьник видит запрос в своём кабинете и отвечает */
  let stS2 = (await j('GET', '/v1/state', null, H.s3.h)).data;
  let orgReq = stS2.requests.find((r) => r.buyerId === 'o1');
  check(!!orgReq, 'школьник видит запрос от организатора');
  let ans = await j('PATCH', `/v1/contact-requests/${orgReq.id}`, { status: 'approved' }, H.s3.h);
  check(ans.status === 200, 'школьник одобрил запрос орг-а');
  let tg2 = (await j('GET', '/v1/talents', null, H.o1.h)).data;
  check(tg2.talents.find((x) => x.id === 's3').contact_open === true, 'после одобрения контакт открыт для этого орг-а');
  /* другой орг этот контакт НЕ видит */
  let tg3 = (await j('GET', '/v1/talents', null, H.o2.h)).data;
  check(tg3.talents.find((x) => x.id === 's3').contact_open === false, 'чужой орг: контакт s3 не открыт');
  /* org не получает чужие запросы в срезе */
  let stOCat = (await j('GET', '/v1/state', null, H.o2.h)).data;
  check(stOCat.requests.length === 0, 'org o2: в срезе только СВОИ запросы (пусто)');
  /* студент не может искать таланты и создавать запросы */
  check((await j('GET', '/v1/talents', null, H.s1.h)).status === 401, 'student: talents → 401');
  check((await j('POST', '/v1/contact-requests', { studentId: 's1', purpose: 'x' }, H.s1.h)).status === 401, 'student: contact-requests → 401');

  section('[persistence] перезапуск сервера');
  const pers = await j('POST', '/v1/contests/k5/certificates', { rows: [{ name: 'Персистентный Тест', grade: 10, city: 'Актобе', school: 'СОШ №1', result: 'finalist' }] }, H.o2.h);
  const persId = pers.data.issued[0];
  await stopServer();
  startServer();
  if (!(await waitUp())) { console.error('Не перезапущен:\n' + srvOut); process.exit(1); }
  const pv = (await j('GET', `/v1/certificates/${persId}/verify`)).data;
  check(pv.found === true && pv.sigOk === true, `после перезапуска ${persId} в базе и подпись верна (данные переживают рестарт)`);
  const stO2 = (await j('GET', '/v1/state', null, H.o2.h)).data;
  check(stO2.certs.length === 3 + 2 + 1, 'счётчик сертификатов o2 сохранён (3 k2 + 2 k5 + 1 персистентный)');
  check((await j('POST', '/v1/login', { login: 'fresh_stu', password: 'pw_stu_1' })).status === 200, 'зарегистрированный аккаунт переживает рестарт');

  section('[reset] детерминизм');
  check((await j('POST', '/v1/reset', {})).status === 200, 'reset 200');
  check((await j('GET', `/v1/certificates/${persId}/verify`)).status === 404, 'reset: выданные сертификаты исчезли');
  check((await j('GET', '/v1/certificates/PRF-GH26-0001/verify')).data.points === 77, 'reset: веса и баллы снова сид-значения');
  check((await j('POST', '/v1/login', { login: 'aigerim', password: 'pfy_demo_s1' })).status === 200, 'reset: демо-аккаунты возвращены');
  check(eq((await j('GET', '/v1/talents', null, H.b1.h)).data.talents.map((x) => x.id), ['s1', 's2', 's3', 's5', 's6']), 'reset: поиск снова сид-состав');
  check((await j('POST', '/v1/login', { login: 'fresh_stu', password: 'pw_stu_1' })).status === 401, 'reset: зарегистрированный аккаунт удалён (сид)');

  await stopServer();
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (e) { /* ignore */ }
}

(async () => {
  console.log('Proofy — строгие тесты (RBAC)\n');
  await unitTests();
  await integrationTests();
  console.log(`\nИтог: ${passed} прошло, ${failed} упало`);
  process.exit(failed ? 1 : 0);
})().catch(async (e) => {
  console.error('Сбой теста:', e);
  if (srv && srv.exitCode === null) await new Promise((r) => { srv.once('exit', () => r()); setTimeout(r, 2500); });
  if (srv) console.error(`сервер: exitCode=${srv.exitCode} signalCode=${srv.signalCode} pid=${srv.pid}`);
  const lines = srvOut.split('\n');
  console.error('--- лог сервера (хвост) ---\n' + lines.slice(-30).join('\n'));
  try { if (srv) srv.kill(); } catch (err) { /* ignore */ }
  process.exit(1);
});

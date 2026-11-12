'use strict';
/* Смоук-тесты API Proofy: поднимает сервер на отдельном порту и гоняет через fetch.
   Запуск: node server/test.js */
const { spawn } = require('node:child_process');
const path = require('node:path');

const PORT = 4199;
const BASE = `http://127.0.0.1:${PORT}`;
let passed = 0, failed = 0;
let srv;

const ok = (cond, name, extra = '') => {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.error(`  ✗ ${name}${extra ? ' — ' + extra : ''}`); }
};
async function j(method, p, body, headers = {}) {
  const res = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* пустой ответ */ }
  return { status: res.status, data };
}

(async () => {
  srv = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let srvOut = '';
  srv.stdout.on('data', (d) => { srvOut += d; });
  srv.stderr.on('data', (d) => { srvOut += d; });

  let up = false;
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(BASE + '/v1/health'); if (r.ok) { up = true; break; } } catch (e) { /* ещё стартует */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!up) { console.error('Сервер не запустился:\n' + srvOut); process.exit(1); }

  console.log('Proofy API — смоук-тесты\n');

  const health = await j('GET', '/v1/health');
  ok(health.status === 200 && health.data.ok === true, 'GET /v1/health');

  const anonState = await j('GET', '/v1/state');
  ok(anonState.status === 401, 'state аноним → 401 (кабинет только после входа)');
  const HS = { Authorization: 'Bearer pfy_demo_s1' };
  const st = (await j('GET', '/v1/state', null, HS)).data;
  ok(st.role === 'student' && st.me?.id === 's1', 'state (токен s1): ролевой срез — только свой кабинет');
  ok(st.students?.length === 1 && st.certs?.length === 2, 'срез школьника: 1 студент (себя), 2 сертификата');
  ok(st.certs?.every((c) => c.sig && c.kid), 'все сертификаты подписаны (sig + kid)');
  ok(!JSON.stringify(st).includes('"d":"'), 'в state нет закрытых ключей');

  const v1 = await j('GET', '/v1/certificates/PRF-GH26-0001/verify');
  ok(v1.status === 200 && v1.data.found === true, 'verify PRF-GH26-0001: найден');
  ok(v1.data.sig_ok === true, 'подпись ECDSA верна');
  ok(v1.data.contest?.weight === 77, 'вес Gambit Hackathon = 77', String(v1.data.contest?.weight));
  ok(v1.data.points === 77, 'баллы победителя = 77');
  ok(v1.data.holder?.display_name === 'А. Н.', 'владелец — инициалы (имя скрыто)', v1.data.holder?.display_name);
  ok(v1.data.cert?.sig && v1.data.cert?.kid, 'cert.sig и cert.kid в ответе');

  const v2 = await j('GET', '/v1/certificates/PRF-GH26-0999/verify');
  ok(v2.status === 404 && v2.data.found === false, 'выдуманный ID → 404 {found:false}');

  const v3 = await j('GET', '/v1/certificates/PRF-OM26-0003/verify?claimed_result=winner');
  ok(v3.data.found === true && v3.data.sig_ok === true, 'PRF-OM26-0003: подпись с настоящим результатом верна');
  ok(v3.data.claimSigOk === false && v3.data.claimed_result_sig_ok === false, 'изменённый результат: подпись с «winner» не сходится');

  const v4 = await j('GET', '/v1/certificates/PRF-SO26-0002/verify');
  ok(v4.data.contest?.weight === 25, 'платный конкурс без отбора: вес = 25', String(v4.data.contest?.weight));
  ok(v4.data.points === Math.round(25 * 1), 'баллы = вес × k');

  const pub = await j('GET', '/v1/orgs/o1/public-key');
  ok(pub.status === 200 && pub.data.jwk?.crv === 'P-256' && /^P-256$/.test(pub.data.jwk?.crv || '') && pub.data.kid, 'открытый ключ организатора (JWK P-256 + kid)');

  const HO = { Authorization: 'Bearer pfy_demo_o1' };
  const iss = await j('POST', '/v1/contests/k1/certificates', { rows: [
    { name: 'Алия Серикова', grade: 10, city: 'Актобе', school: 'СОШ №12', result: 'winner' },
    { name: 'Айгерим Нурланова', grade: 10, city: 'Хромтау', school: 'Школа-гимназия №1', result: 'prize' },
  ] }, HO);
  ok(iss.status === 201 && iss.data.issued?.length === 2, 'выдача (org o1, свой k1): 2 сертификата', JSON.stringify(iss.data));
  ok((await j('POST', '/v1/contests/k3/certificates', { rows: [{ name: 'X', grade: 9, city: 'А', school: 'С', result: 'winner' }] }, HO)).status === 403, 'выдача в чужой конкурс → 403');
  const vNew = await j('GET', `/v1/certificates/${iss.data.issued?.[0] || 'X'}/verify`);
  ok(vNew.data.found === true && vNew.data.sig_ok === true, 'выданный сертификат проходит проверку');

  const cc = await j('POST', '/v1/contests', { name: 'Городская олимпиада по физике', level: 'city', direction: 'Физика', participants: 200, awarded: 15, date: '2026-11-14', selection: true, paid: false }, HO);
  ok(cc.status === 201 && cc.data.contest?.id, 'создание конкурса (org из токена)', JSON.stringify(cc.data));
  const ct = await j('GET', '/v1/contests?direction=' + encodeURIComponent('Физика'));
  ok(ct.status === 200 && ct.data.contests?.some((x) => x.id === cc.data.contest?.id), 'рейтинг конкурсов по направлению');
  ok(ct.data.contests?.[0]?.weight === 57, 'вес новой городской олимпиады = 57 (35+12+10)', String(ct.data.contests?.[0]?.weight));

  const HB = { Authorization: 'Bearer pfy_demo_b1' };
  const tal = (await j('GET', '/v1/talents?min_weight=70', null, HB)).data;
  ok(Array.isArray(tal.talents) && tal.hidden_count === 2, 'поиск (buyer b1): скрыты 2 школьника без согласия (Тимур + новый при выдаче)', JSON.stringify({ n: tal.talents?.length, h: tal.hidden_count }));
  ok(!tal.talents?.some((t) => t.id === 's4'), 'Тимур (без согласия) не в выдаче поиска');
  ok(tal.talents?.find((t) => t.city === 'Хромтау')?.display_name === 'А. Н.', 'в поиске нет полного имени (showName=false)');

  const cr = await j('POST', '/v1/contact-requests', { studentId: 's3', purpose: 'Грант на обучение' }, HB);
  ok(cr.status === 201 && cr.data.request?.status === 'pending' && cr.data.request?.buyerId === 'b1', 'запрос контакта (buyer из токена) → pending');
  const HS3 = { Authorization: 'Bearer pfy_demo_s3' };
  const ans = await j('PATCH', `/v1/contact-requests/${cr.data.request?.id || 'x'}`, { status: 'approved' }, HS3);
  ok(ans.status === 200 && ans.data.ok === true, 'школьник (владелец) одобрил запрос');

  const HS4 = { Authorization: 'Bearer pfy_demo_s4' };
  const badConsent = await j('PATCH', '/v1/students/s4/consent', { field: 'search', value: true }, HS4);
  ok(badConsent.status === 400, 'in_search без согласия родителя → 400');
  const okParent = await j('PATCH', '/v1/students/s4/consent', { field: 'parent', value: true }, HS4);
  ok(okParent.status === 200 && okParent.data.ok === true, 'согласие родителя сохранено (свой аккаунт)');
  const okSearch = await j('PATCH', '/v1/students/s4/consent', { field: 'search', value: true }, HS4);
  ok(okSearch.status === 200, 'in_search после согласия родителя');

  const reg = await j('POST', '/v1/register', { role: 'buyer', name: 'Тестовое агентство (тест)', city: 'Актобе', login: 'smoke_buy', password: 'pw_smoke' });
  ok(reg.status === 201 && reg.data.account?.entityId && reg.data.token === 'pw_smoke', 'регистрация (buyer) → токен', JSON.stringify(reg.data));

  const auth401 = await j('GET', '/v1/talents', null, { Authorization: 'Bearer wrong_key' });
  ok(auth401.status === 401, 'неверный токен → 401');
  const authOk = await j('GET', '/v1/talents', null, HB);
  ok(authOk.status === 200, 'токен покупателя принимается');
  const login = await j('POST', '/v1/login', { login: 'aigerim', password: 'pfy_demo_s1' });
  ok(login.status === 200 && login.data.token === 'pfy_demo_s1', 'вход по логину/паролю → токен');

  const rst = await j('POST', '/v1/reset', {});
  const st2 = (await j('GET', '/v1/state', null, HS)).data;
  ok(rst.status === 200 && st2.certs?.length === 2 && st2.students?.length === 1, 'reset: реестр возвращён к сид-данным (срез s1: 2 сертификата)');

  const sigBytes = Buffer.from(st.certs[0].sig, 'base64url').length;
  ok(sigBytes === 64, 'формат подписи IEEE P1363: ровно 64 байта (r‖s)');

  console.log(`\nИтог: ${passed} прошло, ${failed} упало`);
  srv.kill();
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('Ошибка теста:', e);
  try { srv.kill(); } catch (err) { /* ignore */ }
  process.exit(1);
});

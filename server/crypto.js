'use strict';
/* Подпись сертификатов: ECDSA P-256 / SHA-256, IEEE P1363 (r‖s, 64 байта), base64url без "=".
   Строка подписи (BACKEND.md):
     PROOFY/1|{cert_id}|{org_id}|{contest_name}|{contest_date YYYY-MM-DD}|{student_id}|{result}
   Совместимо с WebCrypto в браузере (тот же JWK, тот же kid). */
const crypto = require('node:crypto');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

/* Пара ключей организатора: JWK + kid (первые 16 hex SHA-256 от x+y), как в genKeys() из app.js */
function genKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ type: 'spki', format: 'jwk' });
  const priv = privateKey.export({ type: 'pkcs8', format: 'jwk' });
  return { kid: sha256hex(pub.x + pub.y).slice(0, 16), pub, priv };
}

const certPayload = (cert, contest, result) =>
  `PROOFY/1|${cert.id}|${contest.orgId}|${contest.name}|${contest.date}|${cert.studentId}|${result}`;

function sign(ks, payload) {
  const key = crypto.createPrivateKey({ key: ks.priv, format: 'jwk' });
  return b64u(crypto.sign('sha256', Buffer.from(payload, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }));
}

function verify(ks, payload, sigB64u) {
  try {
    const key = crypto.createPublicKey({ key: ks.pub, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sigB64u, 'base64url'));
  } catch (e) {
    return false;
  }
}

/* Подписать сертификат (или строку с другим result — для проверки «изменённого результата») */
function signCert(db, cert, result) {
  const k = db.contests.find((x) => x.id === cert.contestId);
  const ks = db.keys[k.orgId];
  const sig = sign(ks, certPayload(cert, k, result !== undefined ? result : cert.result));
  cert.sig = sig;
  cert.kid = ks.kid;
  return sig;
}

function verifyCertSig(db, cert, result) {
  const k = db.contests.find((x) => x.id === cert.contestId);
  if (!k || !cert.sig) return false;
  const ks = db.keys && db.keys[k.orgId];
  if (!ks) return false;
  return verify(ks, certPayload(cert, k, result || cert.result), cert.sig);
}

module.exports = { genKeys, sign, verify, signCert, verifyCertSig, certPayload, sha256hex };

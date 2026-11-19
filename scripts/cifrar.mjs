// Cifra privado/registros.json en data.enc.json (AES-GCM 256, clave PBKDF2-SHA256).
// La contraseña y la sal viven en privado/clave.json, que nunca se sube a GitHub.
// Uso: node scripts/cifrar.mjs
import { readFile, writeFile, access } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';

const ITER = 600000;
const here = new URL('..', import.meta.url);
const p = (f) => new URL(f, here);
const b64 = (buf) => Buffer.from(buf).toString('base64');

async function exists(f) { try { await access(f); return true; } catch { return false; } }

async function clave() {
  const file = p('privado/clave.json');
  if (await exists(file)) return JSON.parse(await readFile(file, 'utf8'));
  const abc = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const rnd = crypto.getRandomValues(new Uint8Array(16));
  const chars = Array.from(rnd, (n) => abc[n % abc.length]).join('');
  const pass = 'tpc-' + chars.match(/.{4}/g).join('-');
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const k = { pass, salt, iter: ITER };
  await writeFile(file, JSON.stringify(k, null, 1));
  console.log('Contraseña nueva guardada en privado/clave.json');
  return k;
}

const k = await clave();
const datos = await readFile(p('privado/registros.json'));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(k.pass), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt: Buffer.from(k.salt, 'base64'), iterations: k.iter, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, datos);
await writeFile(p('data.enc.json'), JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: k.iter, salt: k.salt, iv: b64(iv), ct: b64(ct) }));
console.log('data.enc.json listo (' + Math.round(ct.byteLength / 1024) + ' KB cifrados)');

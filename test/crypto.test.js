import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { DEFAULT_PARAMS, decrypt, encrypt, inspect } from '../src/crypto.js';
import { PREFIX_LENGTH, buildAad, parse, serialize } from '../src/format.js';
import { CHEAP, flipByte } from './helpers.js';

const SENHA = 'senha-de-teste';
const PEPPER = 'pepper-de-teste';

const lock = (content, name = '.env', options = {}) =>
  encrypt(Buffer.from(content), name, SENHA, PEPPER, { params: CHEAP, ...options });

test('ida e volta preserva conteúdo e nome', () => {
  const original = 'API_KEY=abc123\nDB_URL=postgres://localhost/x\n';
  const { name, content } = decrypt(lock(original), SENHA, PEPPER);
  assert.equal(content.toString(), original);
  assert.equal(name, '.env');
});

test('ida e volta com conteúdo binário', () => {
  const original = crypto.randomBytes(4096);
  const { content } = decrypt(lock(original), SENHA, PEPPER);
  assert.ok(content.equals(original));
});

test('ida e volta com arquivo vazio', () => {
  const { content } = decrypt(lock(Buffer.alloc(0)), SENHA, PEPPER);
  assert.equal(content.length, 0);
});

test('ida e volta com 10 MB', () => {
  const original = crypto.randomBytes(10 * 1024 * 1024);
  const { content } = decrypt(lock(original), SENHA, PEPPER);
  assert.ok(content.equals(original));
});

test('nome com acentos e emoji sobrevive', () => {
  const name = 'configuração-produção-🔐.env';
  assert.equal(decrypt(lock('x', name), SENHA, PEPPER).name, name);
});

test('o conteúdo original não aparece em claro no container', () => {
  const container = lock('API_KEY=supersecreto');
  assert.equal(container.includes('supersecreto'), false);
  assert.equal(container.includes('API_KEY'), false);
});

test('o nome do arquivo também fica criptografado', () => {
  const container = lock('x', 'credenciais-do-cliente.env');
  assert.equal(container.includes('credenciais'), false);
});

test('senha errada falha', () => {
  assert.throws(() => decrypt(lock('x'), 'outra-senha', PEPPER), { code: 'EAUTH' });
});

test('pepper errado falha', () => {
  assert.throws(() => decrypt(lock('x'), SENHA, 'outro-pepper'), { code: 'EAUTH' });
});

test('senha e pepper trocados entre si falham', () => {
  assert.throws(() => decrypt(lock('x'), PEPPER, SENHA), { code: 'EAUTH' });
});

test('a mensagem de erro não diz qual dos dois errou', () => {
  const porSenha = (() => { try { decrypt(lock('x'), 'z', PEPPER); } catch (e) { return e.message; } })();
  const porPepper = (() => { try { decrypt(lock('x'), SENHA, 'z'); } catch (e) { return e.message; } })();
  assert.equal(porSenha, porPepper);
});

test('alterar um byte do ciphertext falha', () => {
  const container = lock('conteúdo importante');
  const { ciphertext } = parse(container);
  const offset = container.length - ciphertext.length - 16;
  assert.throws(() => decrypt(flipByte(container, offset), SENHA, PEPPER), { code: 'EAUTH' });
});

test('alterar o cabeçalho falha — o AAD cobre ele', () => {
  const container = lock('x', '.env', { label: 'prod' });
  const headerByte = PREFIX_LENGTH + 2; // dentro do JSON do cabeçalho
  assert.throws(() => decrypt(flipByte(container, headerByte), SENHA, PEPPER), {
    code: /EAUTH|EFORMAT|EINPUT/,
  });
});

test('alterar a tag de autenticação falha', () => {
  const container = lock('x');
  assert.throws(() => decrypt(flipByte(container, container.length - 1), SENHA, PEPPER), {
    code: 'EAUTH',
  });
});

test('truncar o final falha', () => {
  const container = lock('conteúdo longo o suficiente para cortar');
  assert.throws(() => decrypt(container.subarray(0, container.length - 4), SENHA, PEPPER), {
    code: 'EAUTH',
  });
});

test('o mesmo arquivo com a mesma senha gera containers diferentes', () => {
  const a = lock('mesmo conteúdo');
  const b = lock('mesmo conteúdo');
  assert.equal(a.equals(b), false, 'salt/nonce precisam ser sorteados a cada vez');
  assert.notEqual(parse(a).header.salt, parse(b).header.salt);
  assert.notEqual(parse(a).header.nonce, parse(b).header.nonce);
});

test('senha ou pepper vazios são recusados', () => {
  assert.throws(() => encrypt(Buffer.from('x'), '.env', '', PEPPER, { params: CHEAP }), { code: 'EINPUT' });
  assert.throws(() => encrypt(Buffer.from('x'), '.env', SENHA, '', { params: CHEAP }), { code: 'EINPUT' });
  assert.throws(() => decrypt(lock('x'), '', PEPPER), { code: 'EINPUT' });
});

test('o rótulo é legível sem senha, e só ele', () => {
  const info = inspect(lock('segredo', '.env', { label: 'prod-api' }));
  assert.equal(info.label, 'prod-api');
  assert.equal(info.kdf, 'scrypt');
  assert.deepEqual(Object.keys(info).sort(), ['kdf', 'label', 'params', 'version']);
});

test('sem rótulo, inspect devolve null', () => {
  assert.equal(inspect(lock('x')).label, null);
});

test('cabeçalho pedindo memória absurda é recusado antes de chamar o scrypt', () => {
  const { header, ciphertext, tag } = parse(lock('x'));
  const aad = buildAad({ ...header, N: 2 ** 30 });
  assert.throws(() => decrypt(serialize(aad, ciphertext, tag), SENHA, PEPPER), {
    code: 'EINPUT',
    message: /memória/,
  });
});

test('N que não é potência de dois é recusado', () => {
  const { header, ciphertext, tag } = parse(lock('x'));
  const aad = buildAad({ ...header, N: 1000 });
  assert.throws(() => decrypt(serialize(aad, ciphertext, tag), SENHA, PEPPER), {
    code: 'EINPUT',
    message: /potência de dois/,
  });
});

test('kdf desconhecido é recusado com mensagem clara', () => {
  const { header, ciphertext, tag } = parse(lock('x'));
  const aad = buildAad({ ...header, kdf: 'pbkdf2' });
  assert.throws(() => decrypt(serialize(aad, ciphertext, tag), SENHA, PEPPER), {
    code: 'EINPUT',
    message: /pbkdf2/,
  });
});

test('os parâmetros padrão funcionam de ponta a ponta', () => {
  const container = encrypt(Buffer.from('com custo real'), '.env', SENHA, PEPPER);
  assert.deepEqual(inspect(container).params, DEFAULT_PARAMS);
  assert.equal(decrypt(container, SENHA, PEPPER).content.toString(), 'com custo real');
});

test('vetor fixo: o formato não pode mudar sem quebrar este teste', () => {
  const container = encrypt(Buffer.from('API_KEY=vetor\n'), '.env', 'senha', 'pepper', {
    params: { N: 1024, r: 8, p: 1 },
    salt: Buffer.alloc(16, 0xa1),
    nonce: Buffer.alloc(12, 0xb2),
    label: 'vetor',
  });
  assert.equal(container.toString('hex'), '454e564c4f434b000100727b226b6466223a22736372797074222c224e223a313032342c2272223a382c2270223a312c2273616c74223a226f6147686f6147686f6147686f6147686f6147686f513d3d222c226e6f6e6365223a2273724b7973724b7973724b7973724b79222c226c6162656c223a227665746f72227d48eb004c18f5aaef1a2de268f8c12657a15e84b0d37ba1006bd951da091fbd273223fe21');
});

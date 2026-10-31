import assert from 'node:assert/strict';
import test from 'node:test';

import { MAGIC, PREFIX_LENGTH, TAG_LENGTH, buildAad, parse, serialize } from '../src/format.js';

test('serializa e lê de volta', () => {
  const header = { kdf: 'scrypt', N: 1024, label: 'oi' };
  const container = serialize(buildAad(header), Buffer.from('cifra'), Buffer.alloc(TAG_LENGTH, 7));
  const parsed = parse(container);

  assert.equal(parsed.version, 1);
  assert.deepEqual(parsed.header, header);
  assert.equal(parsed.ciphertext.toString(), 'cifra');
  assert.equal(parsed.tag.length, TAG_LENGTH);
});

test('o AAD cobre prefixo e cabeçalho inteiros', () => {
  const header = { kdf: 'scrypt', N: 1024 };
  const aad = buildAad(header);
  const parsed = parse(serialize(aad, Buffer.alloc(0), Buffer.alloc(TAG_LENGTH)));
  assert.ok(parsed.aad.equals(aad));
  assert.equal(parsed.aad.length, PREFIX_LENGTH + JSON.stringify(header).length);
});

test('recusa arquivo que não é envlock', () => {
  const alheio = Buffer.concat([Buffer.from('PK\u0003\u0004isto é um zip'), Buffer.alloc(TAG_LENGTH)]);
  assert.throws(() => parse(alheio), { code: 'EFORMAT', message: /não é um \.envlock/ });
});

test('recusa versão futura com mensagem acionável', () => {
  const container = Buffer.concat([
    MAGIC,
    Buffer.from([99]),
    Buffer.from([0, 0]),
    Buffer.alloc(TAG_LENGTH),
  ]);
  assert.throws(() => parse(container), { code: 'EFORMAT', message: /atualize o envlock/ });
});

test('recusa arquivo truncado', () => {
  const container = serialize(buildAad({ kdf: 'scrypt' }), Buffer.from('x'), Buffer.alloc(TAG_LENGTH));
  assert.throws(() => parse(container.subarray(0, 12)), { code: 'EFORMAT', message: /truncado/ });
});

test('recusa cabeçalho corrompido', () => {
  const container = serialize(buildAad({ kdf: 'scrypt' }), Buffer.alloc(0), Buffer.alloc(TAG_LENGTH));
  container[PREFIX_LENGTH] = 0x40; // troca a chave de abertura do JSON por lixo
  assert.throws(() => parse(container), { code: 'EFORMAT', message: /ilegível/ });
});

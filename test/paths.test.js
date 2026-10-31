import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { safeInnerName, writeFileGuarded } from '../src/paths.js';
import { tempDir } from './helpers.js';

test('aceita nome de arquivo simples', () => {
  assert.equal(safeInnerName('.env'), '.env');
  assert.equal(safeInnerName('config produção.env'), 'config produção.env');
});

test('recusa nome que escaparia do diretório de destino', () => {
  // O nome vem de dentro de um arquivo que outra pessoa montou: ele não pode
  // mandar o envlock gravar em qualquer lugar do disco.
  for (const hostil of ['../../.bashrc', '/etc/passwd', 'sub/dir.env', '..', '.', '']) {
    assert.throws(() => safeInnerName(hostil), { code: 'EPATH' }, `deixou passar ${hostil}`);
  }
});

test('recusa nome com byte nulo', () => {
  assert.throws(() => safeInnerName('.env\u0000.txt'), { code: 'EPATH' });
});

test('não sobrescreve sem --force', (t) => {
  const dir = tempDir(t);
  const file = path.join(dir, 'alvo');
  fs.writeFileSync(file, 'original');

  assert.throws(() => writeFileGuarded(file, Buffer.from('novo')), { code: 'EEXIST' });
  assert.equal(fs.readFileSync(file, 'utf8'), 'original');

  writeFileGuarded(file, Buffer.from('novo'), { force: true });
  assert.equal(fs.readFileSync(file, 'utf8'), 'novo');
});

test('grava com permissão 0600', (t) => {
  const dir = tempDir(t);
  const file = path.join(dir, 'segredo');
  writeFileGuarded(file, Buffer.from('x'));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('sobrescrever também aperta a permissão para 0600', (t) => {
  const dir = tempDir(t);
  const file = path.join(dir, 'segredo');
  fs.writeFileSync(file, 'antigo', { mode: 0o644 });
  fs.chmodSync(file, 0o644);

  writeFileGuarded(file, Buffer.from('novo'), { force: true });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

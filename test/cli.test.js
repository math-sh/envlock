import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { tempDir } from './helpers.js';

const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'envlock.js');
const SENHA = 'senha-cli';
const PEPPER = 'pepper-cli';

/** Em teste os segredos vão por variável de ambiente, como seria num CI. */
function envlock(args, { password = SENHA, pepper = PEPPER } = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ENVLOCK_PASSWORD: password, ENVLOCK_PEPPER: pepper },
  });
  return { code: result.status, out: result.stdout, err: result.stderr };
}

function fixture(t, content = 'API_KEY=abc\nDB=postgres://x\n') {
  const dir = tempDir(t);
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, content);
  return { dir, file, content };
}

test('ida e volta completa pela linha de comando', (t) => {
  const { dir, file, content } = fixture(t);

  const lock = envlock(['lock', file, '--label', 'prod']);
  assert.equal(lock.code, 0, lock.err);
  assert.ok(fs.existsSync(`${file}.envlock`));

  // o .env original sai de cena, como aconteceria antes de enviar o arquivo
  fs.rmSync(file);

  const unlock = envlock(['unlock', `${file}.envlock`]);
  assert.equal(unlock.code, 0, unlock.err);
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), content);
  assert.match(unlock.out, /rótulo deste arquivo: prod/);
});

test('o arquivo criptografado não contém o segredo em claro', (t) => {
  const { file } = fixture(t, 'API_KEY=nao-pode-vazar\n');
  assert.equal(envlock(['lock', file]).code, 0);
  const bytes = fs.readFileSync(`${file}.envlock`);
  assert.equal(bytes.includes('nao-pode-vazar'), false);
  assert.equal(bytes.subarray(0, 7).toString(), 'ENVLOCK');
});

test('senha errada sai com código 3 e não grava nada', (t) => {
  const { dir, file } = fixture(t);
  assert.equal(envlock(['lock', file]).code, 0);
  fs.rmSync(file);

  const unlock = envlock(['unlock', `${file}.envlock`], { password: 'senha-errada' });
  assert.equal(unlock.code, 3);
  assert.match(unlock.err, /senha ou pepper incorretos/);
  assert.equal(fs.existsSync(path.join(dir, '.env')), false);
});

test('pepper errado também não abre', (t) => {
  const { file } = fixture(t);
  assert.equal(envlock(['lock', file]).code, 0);
  fs.rmSync(file);
  assert.equal(envlock(['unlock', `${file}.envlock`], { pepper: 'pepper-errado' }).code, 3);
});

test('não sobrescreve arquivo existente sem --force', (t) => {
  const { dir, file } = fixture(t);
  envlock(['lock', file]);
  fs.writeFileSync(path.join(dir, '.env'), 'o que já estava aqui');

  const semForce = envlock(['unlock', `${file}.envlock`]);
  assert.equal(semForce.code, 1);
  assert.match(semForce.err, /já existe/);
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), 'o que já estava aqui');

  assert.equal(envlock(['unlock', `${file}.envlock`, '--force']).code, 0);
  assert.match(fs.readFileSync(path.join(dir, '.env'), 'utf8'), /API_KEY/);
});

test('-o escolhe o destino', (t) => {
  const { dir, file } = fixture(t);
  const alvo = path.join(dir, 'enviar.envlock');
  assert.equal(envlock(['lock', file, '-o', alvo]).code, 0);
  assert.ok(fs.existsSync(alvo));

  const saida = path.join(dir, 'recebido.env');
  assert.equal(envlock(['unlock', alvo, '-o', saida]).code, 0);
  assert.match(fs.readFileSync(saida, 'utf8'), /API_KEY/);
});

test('info mostra o rótulo e os parâmetros, sem precisar de senha', (t) => {
  const { file } = fixture(t);
  envlock(['lock', file, '--label', 'cliente-x']);
  const info = envlock(['info', `${file}.envlock`], { password: '', pepper: '' });
  assert.equal(info.code, 0);
  assert.match(info.out, /cliente-x/);
  assert.match(info.out, /N=131072/);
});

test('erros de uso saem com código 2', () => {
  assert.equal(envlock(['comando-inexistente']).code, 2);
  assert.equal(envlock(['lock', '/caminho/que/nao/existe']).code, 2);
  assert.equal(envlock(['lock']).code, 2);
  assert.equal(envlock(['lock', 'x', '--opcao-invalida']).code, 2);
});

test('--help e --version saem com código 0', () => {
  const help = envlock(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.out, /envlock lock/);
  assert.match(envlock(['--version']).out, /^\d+\.\d+\.\d+/);
});

test('info recusa arquivo que não é envlock', (t) => {
  const { file } = fixture(t);
  const info = envlock(['info', file]);
  assert.equal(info.code, 1);
  assert.match(info.err, /não é um \.envlock/);
});

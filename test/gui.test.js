import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { encrypt } from '../src/crypto.js';
import { createGuiServer } from '../src/gui/server.js';
import { CHEAP, tempDir } from './helpers.js';

const SENHA = 'senha-gui';
const PEPPER = 'pepper-gui';
const PAGE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'gui', 'index.html');

async function start(t, options = {}) {
  const gui = createGuiServer(options);
  const url = new URL(await gui.listen());
  t.after(() => gui.close());
  const base = `http://127.0.0.1:${url.port}`;
  return {
    gui,
    base,
    page: (token = gui.token) => fetch(`${base}/?t=${encodeURIComponent(token)}`),
    api: (action, body, headers = {}) =>
      fetch(`${base}/api/${action}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-envlock-token': gui.token, ...headers },
        body: JSON.stringify(body),
      }),
  };
}

test('a página exige o token na URL', async (t) => {
  const s = await start(t);
  assert.equal((await fetch(`${s.base}/`)).status, 403);
  assert.equal((await s.page('token-errado')).status, 403);
  assert.equal((await s.page()).status, 200);
});

test('a página entrega o token para o JS da própria página', async (t) => {
  const s = await start(t);
  const html = await (await s.page()).text();
  assert.ok(html.includes(s.gui.token));
  assert.ok(html.includes('<!doctype html>'));
});

test('a API recusa requisição sem token e com token errado', async (t) => {
  const s = await start(t);
  const semToken = await fetch(`${s.base}/api/unlock`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(semToken.status, 403);

  const errado = await s.api('unlock', {}, { 'x-envlock-token': 'nao-e-o-token' });
  assert.equal(errado.status, 403);
});

test('a API recusa corpo que não é JSON (bloqueia POST de formulário)', async (t) => {
  const s = await start(t);
  const response = await s.api('lock', {}, { 'content-type': 'application/x-www-form-urlencoded' });
  assert.equal(response.status, 415);
});

test('recusa Host estranho — barra DNS rebinding', async (t) => {
  const s = await start(t);
  // o fetch do Node não deixa sobrescrever o Host, então falamos HTTP na mão
  const status = await new Promise((resolve, reject) => {
    const socket = net.connect(Number(new URL(s.base).port), '127.0.0.1', () => {
      socket.write(
        [
          'POST /api/unlock HTTP/1.1',
          'Host: arquivo-malicioso.exemplo.com',
          'Content-Type: application/json',
          `X-Envlock-Token: ${s.gui.token}`,
          'Content-Length: 2',
          'Connection: close',
          '',
          '{}',
        ].join('\r\n'),
      );
    });
    let buffer = '';
    socket.on('data', (chunk) => { buffer += chunk; });
    socket.on('error', reject);
    socket.on('end', () => resolve(Number(buffer.split(' ')[1])));
  });
  assert.equal(status, 403);
});

test('recusa Origin de outro site', async (t) => {
  const s = await start(t);
  const response = await s.api('unlock', {}, { origin: 'https://site-qualquer.com' });
  assert.equal(response.status, 403);
});

test('descriptografa arquivo arrastado e devolve para download', async (t) => {
  const s = await start(t);
  const container = encrypt(Buffer.from('API_KEY=xyz\n'), '.env', SENHA, PEPPER, { params: CHEAP });

  const result = await (
    await s.api('unlock', {
      source: 'inline',
      name: 'segredo.envlock',
      content: container.toString('base64'),
      password: SENHA,
      pepper: PEPPER,
    })
  ).json();

  assert.equal(result.ok, true);
  assert.equal(result.delivery, 'download');
  assert.equal(result.name, '.env');
  assert.equal(Buffer.from(result.content, 'base64').toString(), 'API_KEY=xyz\n');
});

test('senha errada pela API devolve erro genérico, não 500', async (t) => {
  const s = await start(t);
  const container = encrypt(Buffer.from('x'), '.env', SENHA, PEPPER, { params: CHEAP });
  const response = await s.api('unlock', {
    source: 'inline',
    name: 'a.envlock',
    content: container.toString('base64'),
    password: 'errada',
    pepper: PEPPER,
  });
  const result = await response.json();
  assert.equal(result.ok, false);
  assert.equal(result.code, 'EAUTH');
  assert.match(result.message, /senha ou pepper/);
});

test('modo alvo grava o arquivo original ao lado', async (t) => {
  const dir = tempDir(t);
  const alvo = path.join(dir, 'enviado.envlock');
  fs.writeFileSync(alvo, encrypt(Buffer.from('SEGREDO=1\n'), '.env', SENHA, PEPPER, { params: CHEAP }));

  const s = await start(t, { targetPath: alvo });
  assert.deepEqual(
    { mode: s.gui.target.mode, name: s.gui.target.name },
    { mode: 'unlock', name: 'enviado.envlock' },
  );

  const result = await (await s.api('unlock', { source: 'target', password: SENHA, pepper: PEPPER })).json();
  assert.equal(result.ok, true);
  assert.equal(result.written, path.join(dir, '.env'));
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), 'SEGREDO=1\n');
});

test('modo alvo não sobrescreve sem confirmação', async (t) => {
  const dir = tempDir(t);
  const alvo = path.join(dir, 'enviado.envlock');
  fs.writeFileSync(alvo, encrypt(Buffer.from('novo\n'), '.env', SENHA, PEPPER, { params: CHEAP }));
  fs.writeFileSync(path.join(dir, '.env'), 'o que já estava aqui');

  const s = await start(t, { targetPath: alvo });
  const primeira = await (await s.api('unlock', { source: 'target', password: SENHA, pepper: PEPPER })).json();
  assert.equal(primeira.code, 'EEXIST');
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), 'o que já estava aqui');

  const segunda = await (
    await s.api('unlock', { source: 'target', password: SENHA, pepper: PEPPER, force: true })
  ).json();
  assert.equal(segunda.ok, true);
  assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), 'novo\n');
});

test('um nome interno hostil não escreve fora da pasta', async (t) => {
  const dir = tempDir(t);
  const alvo = path.join(dir, 'armadilha.envlock');
  fs.writeFileSync(
    alvo,
    encrypt(Buffer.from('rm -rf /\n'), '../../.bashrc', SENHA, PEPPER, { params: CHEAP }),
  );

  const s = await start(t, { targetPath: alvo });
  const result = await (await s.api('unlock', { source: 'target', password: SENHA, pepper: PEPPER })).json();
  assert.equal(result.ok, false);
  assert.equal(result.code, 'EPATH');
  assert.equal(fs.existsSync(path.join(dir, '..', '..', '.bashrc')), false);
});

test('o caminho do alvo nunca vem do navegador', async (t) => {
  const dir = tempDir(t);
  const s = await start(t); // sessão sem alvo
  const result = await (
    await s.api('unlock', {
      source: 'target',
      targetPath: path.join(dir, 'qualquer'),
      password: SENHA,
      pepper: PEPPER,
    })
  ).json();
  assert.equal(result.ok, false);
  assert.match(result.message, /nenhum arquivo alvo/);
});

test('a página não referencia nenhuma URL externa', () => {
  const html = fs.readFileSync(PAGE, 'utf8');
  const externas = html.match(/\b(?:https?:)?\/\/[\w.-]+/g) ?? [];
  assert.deepEqual(externas, [], `a página faria requisições para: ${externas.join(', ')}`);
});

test('a resposta declara CSP sem origens externas', async (t) => {
  const s = await start(t);
  const csp = (await s.page()).headers.get('content-security-policy');
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /connect-src 'self'/);
});

test('rota desconhecida devolve 404', async (t) => {
  const s = await start(t);
  assert.equal((await fetch(`${s.base}/api/qualquer-outra`)).status, 404);
});

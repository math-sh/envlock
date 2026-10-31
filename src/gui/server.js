// Janela gráfica: servidor HTTP efêmero em 127.0.0.1.
//
// Só loopback, porta sorteada pelo sistema, token aleatório de 32 bytes
// exigido em toda requisição, e desliga sozinho. A página não referencia
// nenhuma URL externa, então nenhum byte sai da máquina.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { decrypt, encrypt, inspect } from '../crypto.js';
import {
  EXTENSION,
  defaultLockedName,
  isLocked,
  safeInnerName,
  writeFileGuarded,
} from '../paths.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ASSETS = path.resolve(HERE, '..', '..', 'assets');

const MAX_BODY = 64 * 1024 * 1024;
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const SUCCESS_GRACE_MS = 2500;

function send(res, status, body, contentType = 'application/json; charset=utf-8') {
  const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    // A página só usa recursos próprios e inline; nada de rede externa.
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
  res.end(payload);
}

function tokenMatches(expected, provided) {
  if (typeof provided !== 'string') return false;
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('corpo da requisição grande demais'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text.length === 0 ? {} : JSON.parse(text));
      } catch {
        reject(Object.assign(new Error('JSON inválido'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function describeTarget(targetPath) {
  if (!targetPath) return null;
  const locked = isLocked(targetPath);
  const target = {
    name: path.basename(targetPath),
    dir: path.dirname(targetPath),
    mode: locked ? 'unlock' : 'lock',
    label: null,
    error: null,
  };
  if (locked) {
    try {
      target.label = inspect(fs.readFileSync(targetPath)).label;
    } catch (error) {
      target.error = error.message;
    }
  }
  return target;
}

export function createGuiServer({ targetPath = null } = {}) {
  const token = crypto.randomBytes(32).toString('base64url');
  const target = describeTarget(targetPath);

  let idleTimer = null;
  let shutdownTimer = null;

  const server = http.createServer();

  const resetIdle = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => close(), IDLE_TIMEOUT_MS);
    idleTimer.unref?.();
  };

  const close = () => {
    if (idleTimer) clearTimeout(idleTimer);
    if (shutdownTimer) clearTimeout(shutdownTimer);
    idleTimer = null;
    shutdownTimer = null;
    server.close();
    server.closeAllConnections?.();
  };

  const scheduleShutdown = () => {
    if (shutdownTimer) return;
    shutdownTimer = setTimeout(() => close(), SUCCESS_GRACE_MS);
    shutdownTimer.unref?.();
  };

  const expectedHosts = () => {
    const { port } = server.address() ?? {};
    return [`127.0.0.1:${port}`, `localhost:${port}`];
  };

  /** Barra DNS rebinding (Host estranho) e páginas de outros sites (Origin estranho). */
  const sameOrigin = (req) => {
    const hosts = expectedHosts();
    if (!hosts.includes(req.headers.host)) return false;
    const { origin } = req.headers;
    if (origin === undefined) return true;
    return hosts.some((host) => origin === `http://${host}`);
  };

  const handleOperation = async (action, body) => {
    const { password, pepper, source } = body;
    if (typeof password !== 'string' || typeof pepper !== 'string') {
      throw Object.assign(new Error('senha e pepper são obrigatórios'), { status: 400 });
    }

    // Modo arraste-e-solte: o navegador entrega só o conteúdo, nunca o caminho
    // real. O resultado volta como download, sem tocar o disco.
    if (source === 'inline') {
      const content = Buffer.from(String(body.content ?? ''), 'base64');
      const name = safeInnerName(String(body.name ?? 'arquivo'));
      if (action === 'lock') {
        const result = encrypt(content, name, password, pepper, { label: body.label });
        return { ok: true, delivery: 'download', name: name + EXTENSION, content: result.toString('base64') };
      }
      const result = decrypt(content, password, pepper);
      return {
        ok: true,
        delivery: 'download',
        name: safeInnerName(result.name),
        content: result.content.toString('base64'),
      };
    }

    // Modo alvo: o caminho é o que o servidor já conhecia na inicialização.
    // Um caminho vindo do navegador nunca é aceito.
    if (!targetPath) {
      throw Object.assign(new Error('nenhum arquivo alvo nesta sessão'), { status: 400 });
    }
    const force = body.force === true;
    const input = fs.readFileSync(targetPath);

    if (action === 'lock') {
      const result = encrypt(input, path.basename(targetPath), password, pepper, {
        label: body.label,
      });
      const written = defaultLockedName(targetPath);
      writeFileGuarded(written, result, { force });
      scheduleShutdown();
      return { ok: true, delivery: 'file', written };
    }

    const result = decrypt(input, password, pepper);
    const written = path.join(path.dirname(targetPath), safeInnerName(result.name));
    writeFileGuarded(written, result.content, { force });
    scheduleShutdown();
    return { ok: true, delivery: 'file', written };
  };

  const handleRequest = async (req, res) => {
    resetIdle();
    const url = new URL(req.url, 'http://127.0.0.1');

    if (!sameOrigin(req)) {
      send(res, 403, { ok: false, code: 'EORIGIN', message: 'origem não permitida' });
      return;
    }

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      if (!tokenMatches(token, url.searchParams.get('t'))) {
        send(res, 403, 'token inválido ou ausente', 'text/plain; charset=utf-8');
        return;
      }
      const html = fs
        .readFileSync(path.join(HERE, 'index.html'), 'utf8')
        .replace('__ENVLOCK_BOOTSTRAP__', JSON.stringify({ token, target }).replace(/</g, '\\u003c'));
      send(res, 200, html, 'text/html; charset=utf-8');
      return;
    }

    if (req.method === 'GET' && url.pathname === '/icon.svg') {
      send(res, 200, fs.readFileSync(path.join(ASSETS, 'envlock.svg')), 'image/svg+xml');
      return;
    }

    const action = url.pathname === '/api/lock' ? 'lock' : url.pathname === '/api/unlock' ? 'unlock' : null;
    if (req.method === 'POST' && action) {
      if (!tokenMatches(token, req.headers['x-envlock-token'])) {
        send(res, 403, { ok: false, code: 'ETOKEN', message: 'token inválido ou ausente' });
        return;
      }
      if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) {
        send(res, 415, { ok: false, code: 'ETYPE', message: 'esperado application/json' });
        return;
      }
      try {
        send(res, 200, await handleOperation(action, await readBody(req)));
      } catch (error) {
        send(res, error.status ?? 400, {
          ok: false,
          code: error.code ?? 'EFAIL',
          message: error.message,
        });
      }
      return;
    }

    send(res, 404, { ok: false, code: 'ENOTFOUND', message: 'não encontrado' });
  };

  server.on('request', (req, res) => {
    // Uma rejeição solta aqui derrubaria o processo inteiro no meio da operação.
    handleRequest(req, res).catch((error) => {
      if (res.headersSent) res.destroy();
      else send(res, 500, { ok: false, code: 'EINTERNAL', message: error.message });
    });
  });

  return {
    server,
    token,
    target,
    close,
    listen() {
      return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          resetIdle();
          resolve(`http://127.0.0.1:${server.address().port}/?t=${token}`);
        });
      });
    },
  };
}

function openBrowser(url) {
  const [command, args] =
    process.platform === 'win32'
      ? ['cmd', ['/c', 'start', '""', url.replace(/&/g, '^&')]]
      : process.platform === 'darwin'
        ? ['open', [url]]
        : ['xdg-open', [url]];
  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => {});
    child.unref();
  } catch {
    /* sem navegador: o usuário copia a URL impressa abaixo */
  }
}

export async function startGui({ targetPath = null } = {}) {
  const gui = createGuiServer({ targetPath });
  const url = await gui.listen();
  process.stdout.write(`envlock: janela aberta em ${url}\n`);
  if (targetPath) process.stdout.write(`arquivo: ${targetPath}\n`);
  process.stdout.write('(o servidor é local, exige token e desliga sozinho)\n');
  openBrowser(url);
  await new Promise((resolve) => gui.server.once('close', resolve));
}

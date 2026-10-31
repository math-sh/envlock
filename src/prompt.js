// Leitura de segredos no terminal sem eco, sem dependências.
// Em stdin que não é TTY (pipe, CI) cai para leitura de uma linha.

import { StringDecoder } from 'node:string_decoder';

const CTRL_C = '\u0003';
const CTRL_D = '\u0004';
const CTRL_U = '\u0015';
const BACKSPACE = /[\u0008\u007f]/;

export class PromptCancelled extends Error {
  constructor() {
    super('operação cancelada');
    this.name = 'PromptCancelled';
    this.code = 'ECANCEL';
  }
}

function readLineFromPipe() {
  return new Promise((resolve, reject) => {
    const decoder = new StringDecoder('utf8');
    let buffer = '';
    const onData = (chunk) => {
      buffer += decoder.write(chunk);
      const newline = buffer.indexOf('\n');
      if (newline !== -1) {
        cleanup();
        resolve(buffer.slice(0, newline).replace(/\r$/, ''));
      }
    };
    const onEnd = () => {
      cleanup();
      buffer += decoder.end();
      if (buffer.length === 0) reject(new PromptCancelled());
      else resolve(buffer.replace(/\r?\n$/, ''));
    };
    const cleanup = () => {
      process.stdin.off('data', onData);
      process.stdin.off('end', onEnd);
      process.stdin.off('error', onError);
      process.stdin.pause();
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    process.stdin.on('data', onData);
    process.stdin.once('end', onEnd);
    process.stdin.once('error', onError);
    process.stdin.resume();
  });
}

function readSecretFromTty() {
  return new Promise((resolve, reject) => {
    const decoder = new StringDecoder('utf8');
    let value = '';
    const cleanup = () => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
    };
    const onData = (chunk) => {
      const text = decoder.write(chunk);
      for (const char of text) {
        if (char === '\r' || char === '\n') {
          cleanup();
          process.stdout.write('\n');
          resolve(value);
          return;
        }
        if (char === CTRL_C) {
          cleanup();
          process.stdout.write('\n');
          reject(new PromptCancelled());
          return;
        }
        if (char === CTRL_D) {
          if (value.length === 0) {
            cleanup();
            process.stdout.write('\n');
            reject(new PromptCancelled());
            return;
          }
          continue;
        }
        if (char === CTRL_U) {
          value = '';
          continue;
        }
        if (BACKSPACE.test(char)) {
          value = value.slice(0, -1);
          continue;
        }
        // ignora o resto dos controles (setas chegam como escape + letras)
        if (char >= ' ') value += char;
      }
    };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

/** Pede um segredo, opcionalmente duas vezes para confirmar. */
export async function readSecret(label, { confirm = false } = {}) {
  const ask = async (text) => {
    process.stderr.write(text);
    return process.stdin.isTTY ? readSecretFromTty() : readLineFromPipe();
  };

  for (;;) {
    const value = await ask(`${label}: `);
    if (value.length === 0) {
      process.stderr.write('  (vazio — tente de novo)\n');
      continue;
    }
    if (!confirm) return value;

    const again = await ask(`Confirme ${label.toLowerCase()}: `);
    if (again === value) return value;
    process.stderr.write('  (não conferem — tente de novo)\n');
  }
}

// Utilidades de caminho compartilhadas pela CLI e pela UI.

import fs from 'node:fs';
import path from 'node:path';

export const EXTENSION = '.envlock';

export class EnvlockPathError extends Error {
  constructor(message, code = 'EPATH') {
    super(message);
    this.name = 'EnvlockPathError';
    this.code = code;
  }
}

/**
 * O nome original vem de dentro do arquivo criptografado, que pode ter sido
 * montado por outra pessoa. Um nome como "../../.bashrc" ou "/etc/passwd"
 * gravaria fora do diretório de destino, então só aceitamos um nome simples.
 */
export function safeInnerName(name) {
  const base = path.basename(name);
  if (base !== name || base === '' || base === '.' || base === '..' || base.includes('\0')) {
    throw new EnvlockPathError(
      `o arquivo diz se chamar ${JSON.stringify(name)}, que não é um nome de arquivo simples — use -o para escolher o destino`,
    );
  }
  return base;
}

export function isLocked(filePath) {
  return filePath.toLowerCase().endsWith(EXTENSION);
}

export function defaultLockedName(filePath) {
  return filePath + EXTENSION;
}

/** Grava com 0600 e, por padrão, nunca em cima de um arquivo existente. */
export function writeFileGuarded(target, data, { force = false } = {}) {
  if (!force && fs.existsSync(target)) {
    throw new EnvlockPathError(
      `${target} já existe — use --force para sobrescrever`,
      'EEXIST',
    );
  }
  fs.writeFileSync(target, data, { mode: 0o600, flag: force ? 'w' : 'wx' });
  // `mode` só vale na criação: sobrescrevendo, o arquivo manteria a permissão antiga.
  if (force) fs.chmodSync(target, 0o600);
}

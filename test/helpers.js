import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** scrypt barato: os testes exercitam o formato, não o custo do KDF. */
export const CHEAP = { N: 1024, r: 8, p: 1 };

export function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'envlock-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Vira um bit no byte indicado, devolvendo uma cópia. */
export function flipByte(buffer, index) {
  const copy = Buffer.from(buffer);
  copy[index] ^= 0x01;
  return copy;
}

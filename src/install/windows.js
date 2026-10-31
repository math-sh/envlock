// Associação de arquivo no Windows: HKCU\Software\Classes, sem admin.

import path from 'node:path';
import { spawnSync } from 'node:child_process';

const PROG_ID = 'envlock.file';
const ROOT = 'HKCU\\Software\\Classes';

function reg(args) {
  const result = spawnSync('reg', args, { stdio: ['ignore', 'ignore', 'pipe'] });
  if (result.error) throw new Error(`não consegui rodar o reg.exe: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`reg ${args[0]} falhou: ${String(result.stderr).trim()}`);
  }
}

export function install(packageRoot) {
  const cli = path.join(packageRoot, 'bin', 'envlock.js');
  const icon = path.join(packageRoot, 'assets', 'envlock.ico');

  reg(['add', `${ROOT}\\.envlock`, '/ve', '/d', PROG_ID, '/f']);
  reg(['add', `${ROOT}\\.envlock`, '/v', 'Content Type', '/d', 'application/x-envlock', '/f']);
  reg(['add', `${ROOT}\\${PROG_ID}`, '/ve', '/d', 'Arquivo criptografado envlock', '/f']);
  reg(['add', `${ROOT}\\${PROG_ID}\\DefaultIcon`, '/ve', '/d', `${icon},0`, '/f']);
  reg([
    'add',
    `${ROOT}\\${PROG_ID}\\shell\\open\\command`,
    '/ve',
    '/d',
    `"${process.execPath}" "${cli}" open "%1"`,
    '/f',
  ]);

  process.stdout.write(
    [
      'associação instalada no registro do usuário (HKCU):',
      `  .envlock -> ${PROG_ID}`,
      `  abre com  ${process.execPath} ${cli} open`,
      '',
      'duplo clique num .envlock agora abre a janela do envlock.',
      'se o ícone não trocar na hora, reinicie o Explorer ou faça logoff.',
      '',
    ].join('\n'),
  );
}

export function uninstall() {
  let removed = 0;
  for (const key of [`${ROOT}\\.envlock`, `${ROOT}\\${PROG_ID}`]) {
    const result = spawnSync('reg', ['delete', key, '/f'], { stdio: 'ignore' });
    if (result.status === 0) removed += 1;
  }
  process.stdout.write(removed === 0 ? 'nada para remover\n' : 'associação removida do registro\n');
}

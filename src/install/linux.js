// Associação de arquivo no Linux: tudo sob ~/.local, sem sudo.
//
// Isto roda só quando a pessoa digita `envlock install` — nunca num
// postinstall do npm, que não deve mexer no ambiente de desktop sozinho.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const MIME_TYPE = 'application/x-envlock';
const DESKTOP_ID = 'envlock.desktop';

function dataHome() {
  return process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
}

function targets() {
  const home = dataHome();
  return {
    home,
    mimeDir: path.join(home, 'mime'),
    mimeFile: path.join(home, 'mime', 'packages', 'envlock.xml'),
    appsDir: path.join(home, 'applications'),
    desktopFile: path.join(home, 'applications', DESKTOP_ID),
    iconDir: path.join(home, 'icons', 'hicolor', 'scalable', 'apps'),
    appIcon: path.join(home, 'icons', 'hicolor', 'scalable', 'apps', 'envlock.svg'),
    mimeIcon: path.join(home, 'icons', 'hicolor', 'scalable', 'mimetypes', 'application-x-envlock.svg'),
  };
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'ignore' });
  if (result.error || result.status !== 0) {
    process.stderr.write(`aviso: ${command} não rodou — pode ser preciso relogar para o ícone aparecer\n`);
    return false;
  }
  return true;
}

function refresh(paths) {
  run('update-mime-database', [paths.mimeDir]);
  run('update-desktop-database', [paths.appsDir]);
  spawnSync('gtk-update-icon-cache', ['-qtf', path.join(paths.home, 'icons', 'hicolor')], {
    stdio: 'ignore',
  });
}

export function install(packageRoot) {
  const paths = targets();
  const cli = path.join(packageRoot, 'bin', 'envlock.js');

  for (const dir of [path.dirname(paths.mimeFile), paths.appsDir, paths.iconDir, path.dirname(paths.mimeIcon)]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(
    paths.mimeFile,
    `<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="${MIME_TYPE}">
    <comment>Arquivo criptografado envlock</comment>
    <comment xml:lang="en">envlock encrypted file</comment>
    <glob pattern="*.envlock"/>
    <magic priority="60"><match type="string" value="ENVLOCK" offset="0"/></magic>
    <icon name="application-x-envlock"/>
  </mime-type>
</mime-info>
`,
  );

  // O caminho do node vai explícito: um .desktop não herda o PATH do shell,
  // então "node" sozinho quebra em instalações via nvm/fnm.
  fs.writeFileSync(
    paths.desktopFile,
    `[Desktop Entry]
Type=Application
Version=1.0
Name=envlock
GenericName=Criptografia local de arquivos
Comment=Criptografar e descriptografar arquivos com senha e pepper, sem sair da máquina
Exec="${process.execPath}" "${cli}" open %f
Icon=envlock
Terminal=false
MimeType=${MIME_TYPE};
Categories=Utility;Security;
Keywords=criptografia;env;segredo;encrypt;
StartupNotify=false
`,
    { mode: 0o644 },
  );

  const icon = fs.readFileSync(path.join(packageRoot, 'assets', 'envlock.svg'));
  fs.writeFileSync(paths.appIcon, icon);
  fs.writeFileSync(paths.mimeIcon, icon);

  refresh(paths);
  run('xdg-mime', ['default', DESKTOP_ID, MIME_TYPE]);

  process.stdout.write(
    [
      'associação instalada:',
      `  tipo MIME     ${MIME_TYPE} (*.envlock)`,
      `  aplicativo    ${paths.desktopFile}`,
      '',
      'duplo clique num .envlock agora abre a janela do envlock.',
      'se o ícone ainda não aparecer no gerenciador de arquivos, relogue na sessão.',
      '',
    ].join('\n'),
  );
}

export function uninstall() {
  const paths = targets();
  let removed = 0;
  for (const file of [paths.mimeFile, paths.desktopFile, paths.appIcon, paths.mimeIcon]) {
    if (fs.existsSync(file)) {
      fs.rmSync(file);
      removed += 1;
    }
  }
  refresh(paths);
  process.stdout.write(
    removed === 0 ? 'nada para remover\n' : `associação removida (${removed} arquivos)\n`,
  );
}

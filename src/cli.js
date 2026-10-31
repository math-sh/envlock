import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { decrypt, encrypt, inspect } from './crypto.js';
import { readSecret } from './prompt.js';
import {
  EXTENSION,
  defaultLockedName,
  isLocked,
  safeInnerName,
  writeFileGuarded,
} from './paths.js';

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const HELP = `envlock — criptografia local de arquivos com senha + pepper

Uso:
  envlock lock <arquivo> [--label RÓTULO] [-o SAÍDA] [--force]
  envlock unlock <arquivo${EXTENSION}> [-o SAÍDA] [--force]
  envlock info <arquivo${EXTENSION}>
  envlock open [arquivo]      abre a janela gráfica (local) já no arquivo
  envlock gui                 abre a janela gráfica vazia
  envlock install             associa ${EXTENSION} a esta ferramenta (duplo clique)
  envlock uninstall           desfaz a associação
  envlock --help | --version

Senha e pepper são pedidos interativamente e precisam ser os mesmos na
máquina que criptografa e na que descriptografa. Eles nunca vão dentro do
arquivo: quem receber o arquivo precisa saber os dois.

Em scripts/CI, use as variáveis ENVLOCK_PASSWORD e ENVLOCK_PEPPER — nunca
passe segredo por argumento, pois ele apareceria no \`ps\` e no histórico.
`;

function usageError(message) {
  const error = new Error(message);
  error.code = 'EUSAGE';
  return error;
}

function parseArgs(argv) {
  const options = { positional: [], force: false, label: undefined, output: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (value === undefined) throw usageError(`${arg} precisa de um valor`);
      i += 1;
      return value;
    };
    switch (arg) {
      case '-o':
      case '--output':
        options.output = next();
        break;
      case '--label':
      case '-l':
        options.label = next();
        break;
      case '-f':
      case '--force':
        options.force = true;
        break;
      default:
        if (arg.startsWith('-') && arg !== '-') throw usageError(`opção desconhecida: ${arg}`);
        options.positional.push(arg);
    }
  }
  return options;
}

async function collectSecrets({ confirm }) {
  const password =
    process.env.ENVLOCK_PASSWORD ?? (await readSecret('Senha', { confirm }));
  const pepper = process.env.ENVLOCK_PEPPER ?? (await readSecret('Pepper', { confirm }));
  return { password, pepper };
}

function readInput(filePath) {
  if (!filePath) throw usageError('informe o arquivo');
  if (!fs.existsSync(filePath)) throw usageError(`arquivo não encontrado: ${filePath}`);
  if (!fs.statSync(filePath).isFile()) throw usageError(`não é um arquivo: ${filePath}`);
  return fs.readFileSync(filePath);
}

async function cmdLock(options) {
  const input = options.positional[0];
  const content = readInput(input);
  if (isLocked(input)) {
    process.stderr.write(`aviso: ${input} já tem extensão ${EXTENSION}\n`);
  }
  const { password, pepper } = await collectSecrets({ confirm: true });
  const container = encrypt(content, path.basename(input), password, pepper, {
    label: options.label,
  });
  const target = options.output ?? defaultLockedName(input);
  writeFileGuarded(target, container, { force: options.force });
  process.stdout.write(`criptografado: ${target}\n`);
  if (options.label) process.stdout.write(`rótulo (visível a todos): ${options.label}\n`);
}

async function cmdUnlock(options) {
  const input = options.positional[0];
  const container = readInput(input);
  const info = inspect(container);
  if (info.label) process.stdout.write(`rótulo deste arquivo: ${info.label}\n`);

  const { password, pepper } = await collectSecrets({ confirm: false });
  const { name, content } = decrypt(container, password, pepper);
  const target = options.output ?? path.join(path.dirname(input), safeInnerName(name));
  writeFileGuarded(target, content, { force: options.force });
  process.stdout.write(`descriptografado: ${target}\n`);
}

function cmdInfo(options) {
  const container = readInput(options.positional[0]);
  const info = inspect(container);
  process.stdout.write(
    [
      `formato:  envlock v${info.version}`,
      `derivação: ${info.kdf} (N=${info.params.N}, r=${info.params.r}, p=${info.params.p})`,
      `rótulo:   ${info.label ?? '(nenhum)'}`,
      '',
      'senha e pepper não ficam no arquivo — nada aqui ajuda a abri-lo.',
      '',
    ].join('\n'),
  );
}

async function cmdGui(options) {
  const { startGui } = await import('./gui/server.js');
  const target = options.positional[0] ? path.resolve(options.positional[0]) : null;
  if (target && !fs.existsSync(target)) throw usageError(`arquivo não encontrado: ${target}`);
  await startGui({ targetPath: target });
}

async function cmdInstall(action) {
  const platform = process.platform;
  if (platform === 'linux') {
    const { install, uninstall } = await import('./install/linux.js');
    return action === 'install' ? install(PACKAGE_ROOT) : uninstall();
  }
  if (platform === 'win32') {
    const { install, uninstall } = await import('./install/windows.js');
    return action === 'install' ? install(PACKAGE_ROOT) : uninstall();
  }
  throw usageError(
    `associação de arquivo automática só em Linux e Windows (aqui: ${platform}).\n` +
      `A CLI e o \`envlock gui\` funcionam normalmente.`,
  );
}

function version() {
  const pkg = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8'));
  return pkg.version;
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;

  if (!command || command === '-h' || command === '--help' || command === 'help') {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === '-v' || command === '--version') {
    process.stdout.write(`${version()}\n`);
    return 0;
  }

  try {
    const options = parseArgs(rest);
    switch (command) {
      case 'lock':
      case 'encrypt':
        await cmdLock(options);
        return 0;
      case 'unlock':
      case 'decrypt':
        await cmdUnlock(options);
        return 0;
      case 'info':
        cmdInfo(options);
        return 0;
      case 'open':
      case 'gui':
        await cmdGui(options);
        return 0;
      case 'install':
        await cmdInstall('install');
        return 0;
      case 'uninstall':
        await cmdInstall('uninstall');
        return 0;
      default:
        throw usageError(`comando desconhecido: ${command}`);
    }
  } catch (error) {
    if (error.code === 'EUSAGE') {
      process.stderr.write(`erro: ${error.message}\n\n${HELP}`);
      return 2;
    }
    if (error.code === 'EAUTH') {
      process.stderr.write(`erro: ${error.message}\n`);
      return 3;
    }
    if (error.code === 'ECANCEL') {
      process.stderr.write('cancelado\n');
      return 130;
    }
    process.stderr.write(`erro: ${error.message}\n`);
    return 1;
  }
}

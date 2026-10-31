// Núcleo criptográfico. Camada pura: Buffers entram, Buffers saem.
// Não toca em disco, não lê o terminal, não imprime nada.
//
// AES-256-GCM com chave derivada por scrypt a partir de senha + pepper.
// O pepper entra como chave de um HMAC sobre a senha, em vez de ser
// concatenado: concatenar tornaria senha="ab"/pepper="c" indistinguível
// de senha="a"/pepper="bc".

import crypto from 'node:crypto';
import { buildAad, parse, serialize, TAG_LENGTH } from './format.js';

export const SALT_LENGTH = 16;
export const NONCE_LENGTH = 12;
export const KEY_LENGTH = 32;
export const MAX_NAME_LENGTH = 0xffff;
export const MAX_LABEL_LENGTH = 128;

/** ~128 MiB de memória, ~1-2s num CPU moderno. */
export const DEFAULT_PARAMS = Object.freeze({ N: 2 ** 17, r: 8, p: 1 });
const MAX_SCRYPT_MEM = 512 * 1024 * 1024;

export class EnvlockAuthError extends Error {
  constructor() {
    super('senha ou pepper incorretos, ou arquivo corrompido');
    this.name = 'EnvlockAuthError';
    this.code = 'EAUTH';
  }
}

export class EnvlockInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EnvlockInputError';
    this.code = 'EINPUT';
  }
}

function requireSecrets(password, pepper) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new EnvlockInputError('a senha não pode ficar vazia');
  }
  if (typeof pepper !== 'string' || pepper.length === 0) {
    throw new EnvlockInputError('o pepper não pode ficar vazio');
  }
}

function validateParams({ N, r, p }) {
  const isPositiveInt = (v) => Number.isInteger(v) && v > 0;
  if (!isPositiveInt(N) || !isPositiveInt(r) || !isPositiveInt(p)) {
    throw new EnvlockInputError('parâmetros do scrypt inválidos no cabeçalho');
  }
  if ((N & (N - 1)) !== 0) {
    throw new EnvlockInputError('parâmetro N do scrypt precisa ser potência de dois');
  }
  if (r > 32 || p > 16) {
    throw new EnvlockInputError('parâmetros do scrypt fora da faixa aceita');
  }
  // Um arquivo hostil poderia pedir N absurdo para esgotar a memória da máquina
  // de quem abre. Barramos antes de chamar o scrypt.
  if (128 * N * r > MAX_SCRYPT_MEM) {
    throw new EnvlockInputError('cabeçalho pede mais memória do que o envlock aceita gastar');
  }
  return { N, r, p };
}

function deriveKey(password, pepper, salt, params) {
  const pre = crypto.createHmac('sha256', pepper).update(password, 'utf8').digest();
  try {
    return crypto.scryptSync(pre, salt, KEY_LENGTH, { ...params, maxmem: MAX_SCRYPT_MEM });
  } finally {
    pre.fill(0);
  }
}

/** payload interno: uint16 nameLen | nome (utf8) | conteúdo */
function framePayload(name, content) {
  const nameBytes = Buffer.from(name, 'utf8');
  if (nameBytes.length === 0) {
    throw new EnvlockInputError('nome do arquivo não pode ficar vazio');
  }
  if (nameBytes.length > MAX_NAME_LENGTH) {
    throw new EnvlockInputError('nome do arquivo longo demais');
  }
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(nameBytes.length);
  return Buffer.concat([prefix, nameBytes, content]);
}

function unframePayload(payload) {
  if (payload.length < 2) {
    throw new EnvlockAuthError();
  }
  const nameLength = payload.readUInt16BE(0);
  if (payload.length < 2 + nameLength) {
    throw new EnvlockAuthError();
  }
  return {
    name: payload.subarray(2, 2 + nameLength).toString('utf8'),
    content: Buffer.from(payload.subarray(2 + nameLength)),
  };
}

/**
 * @param {Buffer} content conteúdo original do arquivo
 * @param {string} name nome original, guardado dentro da parte criptografada
 * @param {string} password
 * @param {string} pepper
 * @param {{label?: string, params?: {N:number,r:number,p:number}, salt?: Buffer, nonce?: Buffer}} [options]
 *   `salt` e `nonce` existem só para os vetores de teste; em uso real deixe o
 *   envlock sortear os dois.
 * @returns {Buffer} container .envlock
 */
export function encrypt(content, name, password, pepper, options = {}) {
  requireSecrets(password, pepper);
  if (!Buffer.isBuffer(content)) {
    throw new EnvlockInputError('conteúdo precisa ser um Buffer');
  }

  const params = validateParams({ ...DEFAULT_PARAMS, ...options.params });
  const salt = options.salt ?? crypto.randomBytes(SALT_LENGTH);
  const nonce = options.nonce ?? crypto.randomBytes(NONCE_LENGTH);
  if (salt.length !== SALT_LENGTH) throw new EnvlockInputError('salt com tamanho inválido');
  if (nonce.length !== NONCE_LENGTH) throw new EnvlockInputError('nonce com tamanho inválido');

  let label;
  if (options.label !== undefined && options.label !== null && options.label !== '') {
    if (typeof options.label !== 'string' || options.label.length > MAX_LABEL_LENGTH) {
      throw new EnvlockInputError(`rótulo precisa ser texto de até ${MAX_LABEL_LENGTH} caracteres`);
    }
    // O rótulo fica em texto claro no cabeçalho, então nunca deve conter segredo.
    label = options.label;
  }

  const header = {
    kdf: 'scrypt',
    N: params.N,
    r: params.r,
    p: params.p,
    salt: salt.toString('base64'),
    nonce: nonce.toString('base64'),
    ...(label === undefined ? {} : { label }),
  };

  const aad = buildAad(header);
  const key = deriveKey(password, pepper, salt, params);
  const payload = framePayload(name, content);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LENGTH });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    return serialize(aad, ciphertext, cipher.getAuthTag());
  } finally {
    key.fill(0);
    payload.fill(0);
  }
}

/** Lê o cabeçalho em texto claro sem precisar de senha (usado para mostrar o rótulo). */
export function inspect(container) {
  const { version, header } = parse(container);
  return {
    version,
    kdf: header.kdf,
    label: typeof header.label === 'string' ? header.label : null,
    params: { N: header.N, r: header.r, p: header.p },
  };
}

/**
 * @returns {{name: string, content: Buffer, label: string|null}}
 * @throws {EnvlockAuthError} senha errada, pepper errado ou arquivo alterado —
 *   indistinguíveis de propósito.
 */
export function decrypt(container, password, pepper) {
  requireSecrets(password, pepper);
  const { header, aad, ciphertext, tag } = parse(container);

  if (header.kdf !== 'scrypt') {
    throw new EnvlockInputError(`derivação de chave desconhecida: ${String(header.kdf)}`);
  }
  const params = validateParams({ N: header.N, r: header.r, p: header.p });

  const salt = Buffer.from(String(header.salt ?? ''), 'base64');
  const nonce = Buffer.from(String(header.nonce ?? ''), 'base64');
  if (salt.length !== SALT_LENGTH || nonce.length !== NONCE_LENGTH) {
    throw new EnvlockInputError('salt ou nonce inválido no cabeçalho');
  }

  const key = deriveKey(password, pepper, salt, params);
  let payload;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, {
      authTagLength: TAG_LENGTH,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    payload = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new EnvlockAuthError();
  } finally {
    key.fill(0);
  }

  try {
    const { name, content } = unframePayload(payload);
    return { name, content, label: typeof header.label === 'string' ? header.label : null };
  } finally {
    payload.fill(0);
  }
}

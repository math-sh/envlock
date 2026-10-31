// Serialização do container .envlock
//
// offset  tam  conteúdo
// 0       8    magic "ENVLOCK\0"
// 8       1    versão
// 9       2    hdrLen (uint16 BE)
// 11      N    cabeçalho JSON utf8
// 11+N    ...  ciphertext
// fim-16  16   tag de autenticação GCM
//
// Os bytes de 0 até 11+N formam o AAD: qualquer alteração no cabeçalho
// (salt, parâmetros do scrypt, rótulo) invalida a autenticação.

export const MAGIC = Buffer.from('ENVLOCK\0', 'latin1');
export const VERSION = 1;
export const TAG_LENGTH = 16;
export const PREFIX_LENGTH = MAGIC.length + 1 + 2;
export const MAX_HEADER_LENGTH = 0xffff;

export class EnvlockFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EnvlockFormatError';
    this.code = 'EFORMAT';
  }
}

/** Monta o prefixo + cabeçalho JSON, que juntos são o AAD. */
export function buildAad(header) {
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  if (headerBytes.length > MAX_HEADER_LENGTH) {
    throw new EnvlockFormatError('cabeçalho grande demais');
  }
  const prefix = Buffer.alloc(PREFIX_LENGTH);
  MAGIC.copy(prefix, 0);
  prefix.writeUInt8(VERSION, MAGIC.length);
  prefix.writeUInt16BE(headerBytes.length, MAGIC.length + 1);
  return Buffer.concat([prefix, headerBytes]);
}

export function serialize(aad, ciphertext, tag) {
  return Buffer.concat([aad, ciphertext, tag]);
}

export function parse(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new EnvlockFormatError('esperado um Buffer');
  }
  if (buffer.length < PREFIX_LENGTH + TAG_LENGTH) {
    throw new EnvlockFormatError('arquivo truncado: menor que o cabeçalho mínimo');
  }
  if (!buffer.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new EnvlockFormatError('este arquivo não é um .envlock (assinatura inválida)');
  }
  const version = buffer.readUInt8(MAGIC.length);
  if (version !== VERSION) {
    throw new EnvlockFormatError(
      `arquivo na versão ${version}, esta instalação entende até a ${VERSION} — atualize o envlock`,
    );
  }
  const headerLength = buffer.readUInt16BE(MAGIC.length + 1);
  const headerEnd = PREFIX_LENGTH + headerLength;
  if (buffer.length < headerEnd + TAG_LENGTH) {
    throw new EnvlockFormatError('arquivo truncado: cabeçalho incompleto');
  }

  let header;
  try {
    header = JSON.parse(buffer.subarray(PREFIX_LENGTH, headerEnd).toString('utf8'));
  } catch {
    throw new EnvlockFormatError('cabeçalho ilegível (JSON inválido)');
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    throw new EnvlockFormatError('cabeçalho ilegível (não é um objeto)');
  }

  return {
    version,
    header,
    aad: buffer.subarray(0, headerEnd),
    ciphertext: buffer.subarray(headerEnd, buffer.length - TAG_LENGTH),
    tag: buffer.subarray(buffer.length - TAG_LENGTH),
  };
}

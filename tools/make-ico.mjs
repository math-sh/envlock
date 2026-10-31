// Gera assets/envlock.ico (cadeado azul) nos tamanhos 16/32/48.
// Rodado uma única vez; o .ico vai versionado no pacote.
import fs from 'node:fs';

const BLUE = [0xd8, 0x63, 0x1b]; // BGR de #1b63d8

function draw(size) {
  const s = size / 32;
  const px = new Uint8Array(size * size * 4); // BGRA
  const set = (x, y, rgb, a = 255) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    const i = (y * size + x) * 4;
    px[i] = rgb[0]; px[i + 1] = rgb[1]; px[i + 2] = rgb[2]; px[i + 3] = a;
  };
  const WHITE = [255, 255, 255];

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const fx = x / s, fy = y / s; // coordenadas num grid 32x32

      // arco do cadeado: meio anel superior
      const dx = fx - 16, dy = fy - 13.5;
      const radius = Math.hypot(dx, dy);
      if (fy < 14.5 && radius > 5.2 && radius < 8.2) { set(x, y, BLUE); continue; }

      // corpo com cantos arredondados
      const [x0, x1, y0, y1, r] = [5.5, 26.5, 14, 28.5, 3];
      if (fx >= x0 && fx <= x1 && fy >= y0 && fy <= y1) {
        const cx = Math.min(Math.max(fx, x0 + r), x1 - r);
        const cy = Math.min(Math.max(fy, y0 + r), y1 - r);
        if (Math.hypot(fx - cx, fy - cy) <= r) {
          // buraco da chave
          const kx = fx - 16, ky = fy - 19.5;
          const inKnob = Math.hypot(kx, ky) <= 2.6;
          const inSlot = Math.abs(kx) <= 1.3 && fy >= 19.5 && fy <= 24.5;
          set(x, y, inKnob || inSlot ? WHITE : BLUE);
        }
      }
    }
  }
  return px;
}

function image(size) {
  const px = draw(size);
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  header.writeInt32LE(size * 2, 8); // XOR + AND mask
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(size * size * 4, 20);

  const xor = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    // BMP é bottom-up
    px.subarray((size - 1 - y) * size * 4, (size - y) * size * 4).forEach((b, i) => {
      xor[y * size * 4 + i] = b;
    });
  }
  const maskRow = Math.ceil(size / 32) * 4;
  return Buffer.concat([header, xor, Buffer.alloc(maskRow * size)]);
}

const sizes = [16, 32, 48];
const images = sizes.map(image);
const dir = Buffer.alloc(6 + 16 * sizes.length);
dir.writeUInt16LE(0, 0);
dir.writeUInt16LE(1, 2);
dir.writeUInt16LE(sizes.length, 4);
let offset = dir.length;
sizes.forEach((size, i) => {
  const at = 6 + i * 16;
  dir.writeUInt8(size === 256 ? 0 : size, at);
  dir.writeUInt8(size === 256 ? 0 : size, at + 1);
  dir.writeUInt16LE(1, at + 4);
  dir.writeUInt16LE(32, at + 6);
  dir.writeUInt32LE(images[i].length, at + 8);
  dir.writeUInt32LE(offset, at + 12);
  offset += images[i].length;
});
fs.writeFileSync('assets/envlock.ico', Buffer.concat([dir, ...images]));
console.log('assets/envlock.ico', fs.statSync('assets/envlock.ico').size, 'bytes');

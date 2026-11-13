import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { deflateSync } from "node:zlib";

const SIZES = [16, 32, 48, 256];
const OUTPUT = resolve("desktop/assets/quantic-mail.ico");

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const name = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, crc]);
}
function rounded(x, y, l, t, r, b, radius) {
  const cx = Math.max(l + radius, Math.min(r - radius, x));
  const cy = Math.max(t + radius, Math.min(b - radius, y));
  return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2;
}
function distance(x, y, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const p = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - ax - p * dx, y - ay - p * dy);
}
function png(size) {
  const stride = size * 4 + 1;
  const pixels = Buffer.alloc(stride * size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const px = (x + 0.5) * 256 / size;
      const py = (y + 0.5) * 256 / size;
      const offset = y * stride + 1 + x * 4;
      let red = 0, green = 0, blue = 0, alpha = 0;
      if (rounded(px, py, 10, 10, 246, 246, 56)) {
        const ratio = (px + py) / 512;
        red = Math.round(38 * (1 - ratio) + 23 * ratio);
        green = Math.round(199 * (1 - ratio) + 96 * ratio);
        blue = Math.round(246 * (1 - ratio) + 240 * ratio);
        alpha = 255;
        if (rounded(px, py, 47, 68, 209, 191, 27)) {
          red = 255; green = 255; blue = 255;
          if (distance(px, py, 56, 81, 128, 139) < 7.5 ||
              distance(px, py, 128, 139, 200, 81) < 7.5) {
            red = 19; green = 140; blue = 243;
          }
        }
      }
      pixels[offset] = red;
      pixels[offset + 1] = green;
      pixels[offset + 2] = blue;
      pixels[offset + 3] = alpha;
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(pixels)),
    chunk("IEND", Buffer.alloc(0))
  ]);
}
const images = SIZES.map(png);
const header = Buffer.alloc(6 + images.length * 16);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(images.length, 4);
let offset = header.length;
images.forEach((img, i) => {
  const size = SIZES[i], pos = 6 + i * 16;
  header[pos] = size === 256 ? 0 : size;
  header[pos + 1] = size === 256 ? 0 : size;
  header.writeUInt16LE(1, pos + 4);
  header.writeUInt16LE(32, pos + 6);
  header.writeUInt32LE(img.length, pos + 8);
  header.writeUInt32LE(offset, pos + 12);
  offset += img.length;
});
mkdirSync(dirname(OUTPUT), { recursive: true });
writeFileSync(OUTPUT, Buffer.concat([header, ...images]));
console.log("Icone Windows generee : " + OUTPUT);

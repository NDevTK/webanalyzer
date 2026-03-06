import { writeFileSync } from 'fs';
import { deflateSync } from 'zlib';

function createPNG(size) {
  const pixels = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const cx = size / 2, cy = size / 2, r = size * 0.4;
      const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
      if (dist < r) {
        pixels[idx] = 233; pixels[idx+1] = 69; pixels[idx+2] = 96; pixels[idx+3] = 255;
      } else {
        pixels[idx] = 26; pixels[idx+1] = 26; pixels[idx+2] = 46; pixels[idx+3] = 255;
      }
    }
  }
  const rawData = Buffer.alloc(height(size) * (1 + size * 4));
  for (let y = 0; y < size; y++) {
    const row = y * (1 + size * 4);
    rawData[row] = 0;
    pixels.copy(rawData, row + 1, y * size * 4, (y + 1) * size * 4);
  }
  const compressed = deflateSync(rawData);
  const sig = Buffer.from([137,80,78,71,13,10,26,10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size,0); ihdr.writeUInt32BE(size,4);
  ihdr[8]=8; ihdr[9]=6; ihdr[10]=0; ihdr[11]=0; ihdr[12]=0;
  return Buffer.concat([sig, chunk('IHDR',ihdr), chunk('IDAT',compressed), chunk('IEND',Buffer.alloc(0))]);
}
function height(s){return s;}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length,0);
  const t = Buffer.from(type,'ascii');
  const c = crc32(Buffer.concat([t,data]));
  const cb = Buffer.alloc(4); cb.writeUInt32BE(c,0);
  return Buffer.concat([len,t,data,cb]);
}
function crc32(buf) {
  let c=0xFFFFFFFF;
  for(let i=0;i<buf.length;i++){c^=buf[i];for(let j=0;j<8;j++)c=(c>>>1)^(c&1?0xEDB88320:0);}
  return (c^0xFFFFFFFF)>>>0;
}
for (const size of [16,48,128]) {
  writeFileSync(`src/icons/icon${size}.png`, createPNG(size));
  console.log(`icon${size}.png`);
}

#!/usr/bin/env node
// Takes a snapshot of the Pwned Passwords range API: it reads every SHA-1 prefix from 00000 to
// FFFFF and keeps the `--entries` most prevalent hashes, ordered by count descending, then by hash
// ascending. It writes them as `HASH:COUNT` lines to `--out`, and a summary as JSON to
// `--manifest`.
//
//   node snapshot.mjs --entries 10000000 --out top.txt --manifest manifest.json \
//     [--base-url https://api.pwnedpasswords.com/range/] [--concurrency 32] \
//     [--checkpoint snapshot.checkpoint] [--chunk 65536] [--prefixes 1048576]
//
// Memory is bounded by `--entries` (24 bytes per entry), not by the 2 billion hashes the API
// serves: a min-heap on typed arrays holds the top so far. The prefixes run in chunks, and after
// each chunk the heap goes to `--checkpoint`, so a run that stops resumes from its last chunk.
import { closeSync, existsSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    entries: { type: 'string' },
    out: { type: 'string' },
    manifest: { type: 'string' },
    'base-url': { type: 'string', default: 'https://api.pwnedpasswords.com/range/' },
    concurrency: { type: 'string', default: '32' },
    checkpoint: { type: 'string', default: 'snapshot.checkpoint' },
    chunk: { type: 'string', default: '65536' },
    prefixes: { type: 'string', default: String(0x100000) },
  },
});

const integer = (name, min, max) => {
  const value = Number(values[name]);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    process.stderr.write(`--${name} must be an integer from ${min} to ${max}\n`);
    process.exit(2);
  }
  return value;
};
if (!values.entries || !values.out || !values.manifest) {
  process.stderr.write('usage: snapshot.mjs --entries <n> --out <file> --manifest <file> [options]\n');
  process.exit(2);
}
const ENTRIES = integer('entries', 1, 100_000_000);
const CONCURRENCY = integer('concurrency', 1, 256);
const CHUNK = integer('chunk', 1, 0x100000);
const PREFIXES = integer('prefixes', 1, 0x100000);
const BASE = values['base-url'];
const USER_AGENT = 'pwned-passwords-snapshot';

// The heap: slot `s` holds a hash in hashes[s*20 .. s*20+20) and its count in counts[s]; heap[i]
// is the slot at heap position i. The root is the entry that leaves first: the lowest count, and
// among equal counts the largest hash.
const hashes = new Uint8Array(ENTRIES * 20);
const counts = new Uint32Array(ENTRIES);
const heap = new Int32Array(ENTRIES);
let size = 0;

function compareHash(a, b) {
  const ia = a * 20;
  const ib = b * 20;
  for (let k = 0; k < 20; k += 1) {
    const d = hashes[ia + k] - hashes[ib + k];
    if (d !== 0) return d;
  }
  return 0;
}
// True when slot a leaves before slot b.
const below = (a, b) => (counts[a] !== counts[b] ? counts[a] < counts[b] : compareHash(a, b) > 0);

function siftUp(i) {
  const slot = heap[i];
  while (i > 0) {
    const parent = (i - 1) >> 1;
    if (!below(slot, heap[parent])) break;
    heap[i] = heap[parent];
    i = parent;
  }
  heap[i] = slot;
}
function siftDown(i) {
  const slot = heap[i];
  for (;;) {
    const l = 2 * i + 1;
    if (l >= size) break;
    const r = l + 1;
    const child = r < size && below(heap[r], heap[l]) ? r : l;
    if (!below(heap[child], slot)) break;
    heap[i] = heap[child];
    i = child;
  }
  heap[i] = slot;
}

const HEX = new Int8Array(128).fill(-1);
for (let c = 0; c < 10; c += 1) HEX[48 + c] = c;
for (let c = 0; c < 6; c += 1) {
  HEX[65 + c] = 10 + c;
  HEX[97 + c] = 10 + c;
}
// Writes the 40 hex digits of prefix + suffix into slot's hash bytes.
function writeHash(slot, prefix, text, at) {
  const full = prefix + text.slice(at, at + 35);
  const base = slot * 20;
  for (let k = 0; k < 20; k += 1) {
    const hi = HEX[full.charCodeAt(2 * k)] ?? -1;
    const lo = HEX[full.charCodeAt(2 * k + 1)] ?? -1;
    if (hi < 0 || lo < 0) throw new Error(`range ${prefix}: ${full} is not a SHA-1`);
    hashes[base + k] = (hi << 4) | lo;
  }
}

// A spare slot past the heap would cost a second array; instead a candidate that ties the root's
// count is written into the root's slot only once it is known to win, using this scratch hash.
const scratch = new Uint8Array(20);
function scratchBeatsRoot(prefix, text, at) {
  const full = prefix + text.slice(at, at + 35);
  for (let k = 0; k < 20; k += 1) {
    const hi = HEX[full.charCodeAt(2 * k)] ?? -1;
    const lo = HEX[full.charCodeAt(2 * k + 1)] ?? -1;
    if (hi < 0 || lo < 0) throw new Error(`range ${prefix}: ${full} is not a SHA-1`);
    scratch[k] = (hi << 4) | lo;
  }
  const root = heap[0] * 20;
  for (let k = 0; k < 20; k += 1) {
    const d = hashes[root + k] - scratch[k];
    if (d !== 0) return d > 0; // the root's hash is larger, so it leaves first
  }
  return false;
}

let hashesSeen = 0;
let occurrencesSeen = 0;

// Folds one range response into the heap. Lines are `SUFFIX:COUNT`, 35 hex digits, CRLF.
function consume(prefix, text) {
  let pos = 0;
  const end = text.length;
  while (pos < end) {
    let nl = text.indexOf('\n', pos);
    if (nl === -1) nl = end;
    let stop = nl;
    if (stop > pos && text.charCodeAt(stop - 1) === 13) stop -= 1;
    if (stop > pos) {
      if (text.charCodeAt(pos + 35) !== 58) throw new Error(`range ${prefix}: malformed line at ${pos}`);
      let count = 0;
      for (let k = pos + 36; k < stop; k += 1) {
        const d = text.charCodeAt(k) - 48;
        if (d < 0 || d > 9) throw new Error(`range ${prefix}: malformed count at ${pos}`);
        count = count * 10 + d;
      }
      if (pos + 36 === stop || count > 0xffffffff) throw new Error(`range ${prefix}: bad count at ${pos}`);
      hashesSeen += 1;
      occurrencesSeen += count;
      if (size < ENTRIES) {
        const slot = size;
        size += 1;
        writeHash(slot, prefix, text, pos);
        counts[slot] = count;
        heap[slot] = slot;
        siftUp(slot);
      } else {
        const rootCount = counts[heap[0]];
        if (count > rootCount || (count === rootCount && scratchBeatsRoot(prefix, text, pos))) {
          const slot = heap[0];
          writeHash(slot, prefix, text, pos);
          counts[slot] = count;
          siftDown(0);
        }
      }
    }
    pos = nl + 1;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let retries = 0;
async function fetchRange(prefix) {
  for (let attempt = 1; ; attempt += 1) {
    // A network error, a timeout, 429 and 5xx are retried; any other status stops the run.
    let reason;
    try {
      const response = await fetch(BASE + prefix, {
        headers: { 'user-agent': USER_AGENT },
        signal: AbortSignal.timeout(60_000),
      });
      if (response.status === 200) return await response.text();
      await response.body?.cancel();
      if (response.status !== 429 && response.status < 500) {
        process.stderr.write(`range ${prefix}: HTTP ${response.status}\n`);
        process.exit(1);
      }
      reason = `HTTP ${response.status}`;
    } catch (error) {
      reason = error.message;
    }
    if (attempt >= 12) throw new Error(`range ${prefix}: ${reason} after ${attempt} attempts`);
    retries += 1;
    await sleep(Math.min(60_000, 500 * 2 ** attempt));
  }
}

function saveCheckpoint(nextChunk) {
  const meta = Buffer.from(
    JSON.stringify({ nextChunk, size, entries: ENTRIES, chunk: CHUNK, prefixes: PREFIXES, base: BASE, hashesSeen, occurrencesSeen, retries, started }),
  );
  const length = Buffer.alloc(4);
  length.writeUInt32LE(meta.length);
  const tmp = `${values.checkpoint}.tmp`;
  const fd = openSync(tmp, 'w');
  for (const part of [length, meta, hashes.subarray(0, size * 20), counts.subarray(0, size), heap.subarray(0, size)]) {
    writeSync(fd, part instanceof Buffer ? part : Buffer.from(part.buffer, part.byteOffset, part.byteLength));
  }
  closeSync(fd);
  renameSync(tmp, values.checkpoint);
}

let started = new Date().toISOString();
let firstChunk = 0;
if (existsSync(values.checkpoint)) {
  const file = readFileSync(values.checkpoint);
  const metaLength = file.readUInt32LE(0);
  const meta = JSON.parse(file.subarray(4, 4 + metaLength).toString());
  if (meta.entries !== ENTRIES || meta.chunk !== CHUNK || meta.prefixes !== PREFIXES || meta.base !== BASE) {
    process.stderr.write(`${values.checkpoint} is from a run with other options; remove it to start over\n`);
    process.exit(2);
  }
  let at = 4 + metaLength;
  size = meta.size;
  hashes.set(file.subarray(at, at + size * 20));
  at += size * 20;
  counts.set(new Uint32Array(file.buffer.slice(file.byteOffset + at, file.byteOffset + at + size * 4)));
  at += size * 4;
  heap.set(new Int32Array(file.buffer.slice(file.byteOffset + at, file.byteOffset + at + size * 4)));
  ({ hashesSeen, occurrencesSeen, retries, started } = meta);
  firstChunk = meta.nextChunk;
  process.stderr.write(`resuming at chunk ${firstChunk} with ${size} entries\n`);
}

const chunks = Math.ceil(PREFIXES / CHUNK);
const t0 = Date.now();
for (let chunk = firstChunk; chunk < chunks; chunk += 1) {
  const from = chunk * CHUNK;
  const to = Math.min(PREFIXES, from + CHUNK);
  let next = from;
  const worker = async () => {
    while (next < to) {
      const prefix = next.toString(16).toUpperCase().padStart(5, '0');
      next += 1;
      consume(prefix, await fetchRange(prefix));
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, to - from) }, worker));
  saveCheckpoint(chunk + 1);
  const minutes = ((Date.now() - t0) / 60_000).toFixed(1);
  process.stderr.write(
    `chunk ${chunk + 1}/${chunks}: prefixes to ${to}, ${hashesSeen} hashes seen, lowest kept count ${size === ENTRIES ? counts[heap[0]] : 0}, ${retries} retries, ${minutes} min\n`,
  );
}

// Count descending, then hash ascending: the order build.mjs keeps.
const order = heap.slice(0, size).sort((a, b) => (counts[a] !== counts[b] ? counts[b] - counts[a] : compareHash(a, b)));
const fd = openSync(`${values.out}.tmp`, 'w');
const DIGITS = '0123456789ABCDEF';
let buffer = '';
for (let i = 0; i < order.length; i += 1) {
  const base = order[i] * 20;
  let line = '';
  for (let k = 0; k < 20; k += 1) line += DIGITS[hashes[base + k] >> 4] + DIGITS[hashes[base + k] & 15];
  buffer += `${line}:${counts[order[i]]}\n`;
  if (buffer.length > 1 << 20) {
    writeSync(fd, buffer);
    buffer = '';
  }
}
writeSync(fd, buffer);
closeSync(fd);
renameSync(`${values.out}.tmp`, values.out);

const manifest = {
  source: BASE,
  prefixes: PREFIXES,
  started,
  finished: new Date().toISOString(),
  hashes_seen: hashesSeen,
  occurrences_seen: occurrencesSeen,
  entries: size,
  highest_count: size > 0 ? counts[order[0]] : null,
  lowest_count: size > 0 ? counts[order[size - 1]] : null,
  retries,
};
const mfd = openSync(values.manifest, 'w');
writeSync(mfd, `${JSON.stringify(manifest, null, 2)}\n`);
closeSync(mfd);
rmSync(values.checkpoint, { force: true });
process.stderr.write(`${JSON.stringify(manifest)}\n`);

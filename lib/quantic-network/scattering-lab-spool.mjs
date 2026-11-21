// Experimental ciphertext-only handoff to Quantic Scattering V7.1.
// No network, identity database, wallet, auth token, or private key access.
import { createHash, timingSafeEqual, randomUUID } from "node:crypto";
import { open, mkdir, lstat, link, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
const MAGIC = Buffer.from("QS69Q001");
const HEADER = 16, FRAME = 168, DIGEST = 32, MAX = 30000;
const LIMIT = HEADER + MAX * FRAME + DIGEST;

export function validateLabSpool(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < HEADER + FRAME + DIGEST || bytes.length > LIMIT)
    throw new Error("invalid lab spool length");
  if (!bytes.subarray(0, 8).equals(MAGIC)) throw new Error("invalid lab spool format");
  const count = bytes.readUInt32BE(8);
  if (count < 1 || count > MAX || bytes.readUInt32BE(12) !== FRAME ||
      bytes.length !== HEADER + count * FRAME + DIGEST)
    throw new Error("invalid lab spool dimensions");
  const digest = createHash("sha256").update(bytes.subarray(0, -DIGEST)).digest();
  if (!timingSafeEqual(digest, bytes.subarray(-DIGEST))) throw new Error("lab spool damaged");
  return count;
}

// Caller must choose a separate local lab directory. Never point at a production queue.
// SHA-256 is a corruption check, NOT authentication against a writer with local access.
export async function publishLabSpool({ labOnly, source, queueRoot }) {
  if (labOnly !== true) throw new Error("synthetic laboratory opt-in required");
  if (typeof source !== "string" || typeof queueRoot !== "string" || !source || !queueRoot)
    throw new Error("explicit local paths required");
  const dir = resolve(queueRoot, "scattering-lab");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const ds = await lstat(dir);
  if (!ds.isDirectory() || ds.isSymbolicLink()) throw new Error("invalid lab directory");
  if (process.platform !== "win32" && (ds.mode & 0o077) !== 0)
    throw new Error("lab directory must be private");
  const ss = await lstat(source);
  if (!ss.isFile() || ss.size < HEADER + FRAME + DIGEST || ss.size > LIMIT)
    throw new Error("invalid source file");
  const handle = await open(source, "r");
  let bytes;
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.size !== ss.size || st.ino !== ss.ino || st.dev !== ss.dev)
      throw new Error("source changed");
    bytes = Buffer.alloc(st.size);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length-offset, offset);
      if (!result.bytesRead) throw new Error("source truncated");
      offset += result.bytesRead;
    }
    if ((await handle.stat()).size !== bytes.length) throw new Error("source resized");
  } finally { await handle.close(); }
  const frames = validateLabSpool(bytes);
  const id = randomUUID();
  const tmp = join(dir, id + ".tmp");
  const ready = join(dir, id + ".ready");
  const out = await open(tmp, "wx", 0o600);
  try {
    try { await out.writeFile(bytes); await out.sync(); } finally { await out.close(); }
    await link(tmp, ready); // Atomic publication without overwrite; fail if FS lacks hard links.
  } finally { await unlink(tmp); }
  return { frames, path: ready, protection: "lab-only", productionEnabled: false };
}

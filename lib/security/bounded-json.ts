export class RequestBodyError extends Error {
  constructor(message: string, public readonly status: number) { super(message); }
}
export async function readBoundedJson(request: Request, limit: number): Promise<Record<string, unknown>> {
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) {
    throw new RequestBodyError("Requête trop volumineuse.", 413);
  }
  if (!request.body) throw new RequestBodyError("Requête invalide.", 400);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        void reader.cancel().catch(() => {});
        throw new RequestBodyError("Requête trop volumineuse.", 413);
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  try {
    const data = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(data));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("object required");
    return parsed as Record<string, unknown>;
  } catch { throw new RequestBodyError("Requête invalide.", 400); }
}

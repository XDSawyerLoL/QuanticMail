import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";

const COOKIE_NAME = "qm_session";
const MAX_AGE_SECONDS = 60 * 60 * 8;

export type MailSession = {
  email: string;
  authorization: string;
  expiresAt: number;
};

function key() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters");
  }
  return createHash("sha256").update(secret).digest();
}

function encrypt(value: MailSession) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}

function decrypt(token: string): MailSession | null {
  try {
    const buffer = Buffer.from(token, "base64url");
    if (buffer.length < 29) return null;
    const iv = buffer.subarray(0, 12);
    const tag = buffer.subarray(12, 28);
    const encrypted = buffer.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", key(), iv);
    decipher.setAuthTag(tag);
    const payload = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]).toString("utf8");
    const session = JSON.parse(payload) as MailSession;
    if (!session.email || !session.authorization || session.expiresAt <= Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

export async function createSession(email: string, authorization: string) {
  const store = await cookies();
  const session: MailSession = {
    email,
    authorization,
    expiresAt: Date.now() + MAX_AGE_SECONDS * 1000,
  };

  store.set(COOKIE_NAME, encrypt(session), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: MAX_AGE_SECONDS,
  });
}

export async function readSession() {
  const store = await cookies();
  const token = store.get(COOKIE_NAME)?.value;
  return token ? decrypt(token) : null;
}

export async function destroySession() {
  const store = await cookies();
  store.set(COOKIE_NAME, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
}

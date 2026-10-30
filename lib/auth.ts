import "server-only";
import { createHmac, scryptSync, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";

const COOKIE_NAME = "phishguard_demo_session";
const SESSION_SECONDS = 60 * 60 * 8;
const DEMO_ACCOUNTS = [
  { id: "demo-analyst", name: "Demo Analyst", email: "analyst@demo.phishguard.ai", password: "AnalystDemo2026!" },
  { id: "demo-student", name: "Demo Student", email: "student@demo.phishguard.ai", password: "StudentDemo2026!" },
];

export type AuthUser = { id: string; name: string; email: string };
type Session = AuthUser & { expiresAt: number };

function signingSecret() {
  return process.env.AUTH_SECRET || (process.env.NODE_ENV !== "production" ? "local-development-only-change-me" : "");
}

function signature(payload: string) {
  const secret = signingSecret();
  if (!secret) throw new Error("AUTH_SECRET must be set in production.");
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function authenticateDemoAccount(email: string, password: string): AuthUser | null {
  const normalizedEmail = email.trim().toLowerCase();
  const account = DEMO_ACCOUNTS.find((candidate) => candidate.email === normalizedEmail);
  if (!account) return null;
  const submitted = scryptSync(password, account.id, 32);
  const expected = scryptSync(account.password, account.id, 32);
  if (!timingSafeEqual(submitted, expected)) return null;
  return { id: account.id, name: account.name, email: account.email };
}

export function createSessionToken(user: AuthUser) {
  const payload = Buffer.from(JSON.stringify({ ...user, expiresAt: Date.now() + SESSION_SECONDS * 1000 } satisfies Session)).toString("base64url");
  return `${payload}.${signature(payload)}`;
}

export async function getSession(): Promise<AuthUser | null> {
  const token = (await cookies()).get(COOKIE_NAME)?.value;
  if (!token) return null;
  const [payload, suppliedSignature, extra] = token.split(".");
  if (!payload || !suppliedSignature || extra) return null;
  try {
    const expectedSignature = signature(payload);
    const expected = Buffer.from(expectedSignature);
    const supplied = Buffer.from(suppliedSignature);
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Session;
    if (typeof session.id !== "string" || typeof session.name !== "string" || typeof session.email !== "string" || !Number.isFinite(session.expiresAt) || session.expiresAt <= Date.now()) return null;
    if (!DEMO_ACCOUNTS.some((account) => account.id === session.id && account.email === session.email)) return null;
    return { id: session.id, name: session.name, email: session.email };
  } catch {
    return null;
  }
}

export function sessionCookieOptions() {
  return { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax" as const, path: "/", maxAge: SESSION_SECONDS };
}

export function sessionCookieName() {
  return COOKIE_NAME;
}

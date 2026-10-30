import { NextRequest, NextResponse } from "next/server";
import { authenticateDemoAccount, createSessionToken, sessionCookieOptions, sessionCookieName } from "@/lib/auth";

export const runtime = "nodejs";

const attempts = new Map<string, { count: number; resetAt: number }>();

function originIsValid(request: NextRequest) {
  const origin = request.headers.get("origin");
  return !origin || origin === request.nextUrl.origin;
}

function isRateLimited(request: NextRequest) {
  const address = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const now = Date.now();
  if (attempts.size > 1_000) for (const [key, value] of attempts) if (value.resetAt <= now) attempts.delete(key);
  const existing = attempts.get(address);
  if (!existing || existing.resetAt <= now) {
    attempts.set(address, { count: 1, resetAt: now + 15 * 60 * 1000 });
    return false;
  }
  existing.count += 1;
  return existing.count > 15;
}

export async function POST(request: NextRequest) {
  if (!originIsValid(request)) return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
  if (isRateLimited(request)) return NextResponse.json({ error: "Too many sign-in attempts. Try again later." }, { status: 429 });
  try {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 2_000) return NextResponse.json({ error: "Invalid sign-in request." }, { status: 413 });
    const raw = await request.text();
    if (raw.length > 2_000) return NextResponse.json({ error: "Invalid sign-in request." }, { status: 413 });
    const body = JSON.parse(raw) as { email?: unknown; password?: unknown };
    if (typeof body.email !== "string" || typeof body.password !== "string" || body.password.length > 256) return NextResponse.json({ error: "Enter a valid demo email and password." }, { status: 400 });
    const user = authenticateDemoAccount(body.email, body.password);
    if (!user) return NextResponse.json({ error: "That demo email or password is incorrect." }, { status: 401 });
    const response = NextResponse.json({ user });
    response.cookies.set(sessionCookieName(), createSessionToken(user), sessionCookieOptions());
    return response;
  } catch {
    return NextResponse.json({ error: "Sign-in is not configured. Set AUTH_SECRET in the deployment environment." }, { status: 503 });
  }
}

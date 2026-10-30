import { randomUUID } from "node:crypto";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { classify, type Analysis, type RiskClass } from "@/lib/analyzer";
import { ensureScanSchema, turso } from "@/lib/turso";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COOKIE_NAME = "phishguard_workspace";
const COOKIE_AGE_SECONDS = 60 * 60 * 24 * 30;
const MAX_HISTORY = 30;

type ScanType = "Email" | "URL" | "HTML";

async function getWorkspace() {
  const store = await cookies();
  const existing = store.get(COOKIE_NAME)?.value;
  const valid = existing && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(existing);
  return { id: valid ? existing : randomUUID(), isNew: !valid };
}

function withWorkspaceCookie(response: NextResponse, id: string, isNew: boolean) {
  if (isNew) {
    response.cookies.set(COOKIE_NAME, id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: COOKIE_AGE_SECONDS,
    });
  }
  return response;
}

function unavailable() {
  return NextResponse.json({ error: "Turso is not configured." }, { status: 503 });
}

function validOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  return !origin || origin === request.nextUrl.origin;
}

function storedAnalysis(score: number): Analysis {
  return {
    score,
    classification: classify(score),
    indicators: [{ title: "Detailed results not stored", detail: "Only the score and scan category were saved to protect the submitted content.", points: 0 }],
    recommendations: ["Run the scan again to view its local rule explanations."],
  };
}

function displaySummary(type: ScanType) {
  return type === "Email" ? "Email message" : type === "URL" ? "URL analysis" : "HTML snippet analysis";
}

export async function GET() {
  if (!turso) return unavailable();
  const workspace = await getWorkspace();
  try {
    await ensureScanSchema();
    await turso.execute({ sql: "DELETE FROM scans WHERE created_at < ?", args: [new Date(Date.now() - COOKIE_AGE_SECONDS * 1000).toISOString()] });
    const result = await turso.execute({
      sql: "SELECT id, scan_type, score, classification, created_at FROM scans WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ?",
      args: [workspace.id, MAX_HISTORY],
    });
    const scans = result.rows.map((row) => {
      const type = String(row.scan_type) as ScanType;
      const score = Number(row.score);
      return { id: String(row.id), type, summary: displaySummary(type), score, classification: String(row.classification) as RiskClass, time: String(row.created_at), analysis: storedAnalysis(score) };
    });
    return withWorkspaceCookie(NextResponse.json({ scans }), workspace.id, workspace.isNew);
  } catch {
    return NextResponse.json({ error: "Could not load scan history from Turso." }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  if (!turso) return unavailable();
  if (!validOrigin(request)) return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 1_000) return NextResponse.json({ error: "Scan record is too large." }, { status: 413 });
  const workspace = await getWorkspace();
  try {
    const rawBody = await request.text();
    if (rawBody.length > 1_000) return NextResponse.json({ error: "Scan record is too large." }, { status: 413 });
    let body: { id?: unknown; type?: unknown; score?: unknown };
    try { body = JSON.parse(rawBody) as typeof body; } catch { return NextResponse.json({ error: "Invalid scan record." }, { status: 400 }); }
    const types: ScanType[] = ["Email", "URL", "HTML"];
    if (typeof body.id !== "string" || !/^[0-9a-f-]{36}$/i.test(body.id) || typeof body.type !== "string" || !types.includes(body.type as ScanType) || !Number.isInteger(body.score) || Number(body.score) < 0 || Number(body.score) > 100) return NextResponse.json({ error: "Invalid scan record." }, { status: 400 });
    const score = Number(body.score);
    const classification = classify(score);
    await ensureScanSchema();
    const createdAt = new Date().toISOString();
    await turso.execute({
      sql: "INSERT OR REPLACE INTO scans (id, workspace_id, scan_type, score, classification, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      args: [body.id, workspace.id, body.type, score, classification, createdAt],
    });
    await turso.execute({
      sql: "DELETE FROM scans WHERE workspace_id = ? AND id NOT IN (SELECT id FROM scans WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ?)",
      args: [workspace.id, workspace.id, MAX_HISTORY],
    });
    const scan = { id: body.id, type: body.type, summary: displaySummary(body.type as ScanType), score, classification, time: createdAt, analysis: storedAnalysis(score) };
    return withWorkspaceCookie(NextResponse.json({ scan }, { status: 201 }), workspace.id, workspace.isNew);
  } catch {
    return NextResponse.json({ error: "Could not save scan history to Turso." }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  if (!turso) return unavailable();
  if (!validOrigin(request)) return NextResponse.json({ error: "Invalid request origin." }, { status: 403 });
  const workspace = await getWorkspace();
  try {
    await ensureScanSchema();
    await turso.execute({ sql: "DELETE FROM scans WHERE workspace_id = ?", args: [workspace.id] });
    return withWorkspaceCookie(NextResponse.json({ ok: true }), workspace.id, workspace.isNew);
  } catch {
    return NextResponse.json({ error: "Could not clear scan history from Turso." }, { status: 500 });
  }
}

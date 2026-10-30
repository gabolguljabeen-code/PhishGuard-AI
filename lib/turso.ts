import { createClient } from "@libsql/client";

const databaseUrl = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

export const turso = databaseUrl && authToken
  ? createClient({ url: databaseUrl, authToken })
  : null;

let schemaReady: Promise<void> | undefined;

export async function ensureScanSchema() {
  if (!turso) throw new Error("Turso is not configured.");
  schemaReady ??= (async () => {
    await turso.execute(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        scan_type TEXT NOT NULL CHECK (scan_type IN ('Email', 'URL', 'HTML')),
        score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
        classification TEXT NOT NULL CHECK (classification IN ('Low Risk', 'Suspicious', 'High Risk')),
        created_at TEXT NOT NULL
      )
    `);
    await turso.execute("CREATE INDEX IF NOT EXISTS scans_workspace_created ON scans(workspace_id, created_at DESC)");
  })().catch((error) => {
    schemaReady = undefined;
    throw error;
  });
  await schemaReady;
}

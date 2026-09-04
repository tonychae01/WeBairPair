import blossom from "edmonds-blossom";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  APP_URL: string;
  ENVIRONMENT: string;
  AWS_REGION: string;
  SES_FROM_EMAIL: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
}

type Action = "opt_in" | "opt_out";

const TOKEN_TTL_MINUTES = 30;
const encoder = new TextEncoder();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/api/request-verification") {
      return requestVerification(request, env);
    }

    if (request.method === "GET" && url.pathname === "/verify") {
      return verifyAction(url, env);
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Not found." }, 404);
    }

    return env.ASSETS.fetch(request);
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(runMonthlyPairing(env));
  },
} satisfies ExportedHandler<Env>;

async function requestVerification(request: Request, env: Env): Promise<Response> {
  let body: { email?: unknown; action?: unknown };
  try {
    body = await request.json();
  } catch {
    return json({ error: "Please enter a valid Berkeley email." }, 400);
  }

  const email = typeof body.email === "string" ? normalizeEmail(body.email) : "";
  const action = body.action;
  if (!isBerkeleyEmail(email)) {
    return json({ error: "Use your @berkeley.edu email address." }, 400);
  }
  if (action !== "opt_in" && action !== "opt_out") {
    return json({ error: "Invalid request." }, 400);
  }

  const now = new Date();
  const windowStart = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
  const ip = request.headers.get("CF-Connecting-IP") ?? "local";
  const ipHash = await sha256Hex(ip);
  const limits = await env.DB.batch([
    env.DB.prepare(
      "SELECT COUNT(*) AS count FROM verification_requests WHERE email = ? AND created_at >= ?",
    ).bind(email, windowStart),
    env.DB.prepare(
      "SELECT COUNT(*) AS count FROM verification_requests WHERE ip_hash = ? AND created_at >= ?",
    ).bind(ipHash, windowStart),
  ]);
  const emailCount = Number((limits[0].results[0] as { count: number }).count);
  const ipCount = Number((limits[1].results[0] as { count: number }).count);
  if (emailCount >= 3 || ipCount >= 12) {
    return json({ error: "Too many requests. Please try again later." }, 429);
  }

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(now.getTime() + TOKEN_TTL_MINUTES * 60 * 1000).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM verification_tokens WHERE email = ? AND action = ?").bind(email, action),
    env.DB.prepare(
      "INSERT INTO verification_tokens (token_hash, email, action, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    ).bind(tokenHash, email, action, expiresAt, now.toISOString()),
    env.DB.prepare(
      "INSERT INTO verification_requests (email, ip_hash, created_at) VALUES (?, ?, ?)",
    ).bind(email, ipHash, now.toISOString()),
  ]);

  const verificationUrl = `${env.APP_URL.replace(/\/$/, "")}/verify?token=${encodeURIComponent(token)}`;
  const verb = action === "opt_in" ? "join" : "leave";
  await sendEmail(env, {
    to: [email],
    subject: `${capitalize(verb)} WeBairPair`,
    text: `Use this link within ${TOKEN_TTL_MINUTES} minutes to ${verb} WeBairPair:\n\n${verificationUrl}\n\nIf you did not request this, you can ignore this email.`,
    html: emailLayout(
      `${capitalize(verb)} WeBairPair`,
      `<p>Use the button below within ${TOKEN_TTL_MINUTES} minutes to ${verb} WeBairPair.</p><p><a class="button" href="${escapeHtml(verificationUrl)}">Confirm</a></p><p class="muted">If you did not request this, you can ignore this email.</p>`,
    ),
  });

  const response: Record<string, string> = { message: "Check your Berkeley inbox for a confirmation link." };
  if (env.ENVIRONMENT === "development" && !hasSesCredentials(env)) {
    response.verificationUrl = verificationUrl;
  }
  return json(response);
}

async function verifyAction(url: URL, env: Env): Promise<Response> {
  const token = url.searchParams.get("token");
  if (!token) return verificationPage("That link is invalid.", false);

  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    "SELECT email, action, expires_at FROM verification_tokens WHERE token_hash = ?",
  ).bind(tokenHash).first<{ email: string; action: Action; expires_at: string }>();

  if (!row || Date.parse(row.expires_at) <= Date.now()) {
    if (row) {
      await env.DB.prepare("DELETE FROM verification_tokens WHERE token_hash = ?").bind(tokenHash).run();
    }
    return verificationPage("That link has expired or has already been used. Please request a new one.", false);
  }

  const now = new Date().toISOString();
  const optedIn = row.action === "opt_in" ? 1 : 0;
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO users (email, opted_in, created_at, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(email) DO UPDATE SET opted_in = excluded.opted_in, updated_at = excluded.updated_at`,
    ).bind(row.email, optedIn, now, now),
    env.DB.prepare("DELETE FROM verification_tokens WHERE token_hash = ?").bind(tokenHash),
  ]);

  return verificationPage(
    optedIn ? "You’re in. We’ll email you when it’s time to meet your next pair." : "You’re opted out. You can rejoin anytime.",
    true,
  );
}

export async function runMonthlyPairing(env: Env, date = new Date()): Promise<void> {
  const month = date.toISOString().slice(0, 7);
  const existing = await env.DB.prepare(
    "SELECT status, unmatched_email, unmatched_sent FROM pairing_runs WHERE month = ?",
  )
    .bind(month)
    .first<{ status: string; unmatched_email: string | null; unmatched_sent: number }>();
  if (existing?.status === "completed") return;

  let unmatchedEmail = existing?.unmatched_email ?? undefined;
  let unmatchedSent = existing?.unmatched_sent ?? 0;
  if (!existing) {
    const users = await env.DB.prepare(
      "SELECT email, last_unmatched_at FROM users WHERE opted_in = 1 ORDER BY email",
    ).all<{ email: string; last_unmatched_at: string | null }>();
    const emails = users.results.map((row) => row.email);
    secureShuffle(emails);
    const history = await env.DB.prepare("SELECT email_a, email_b FROM pairings")
      .all<{ email_a: string; email_b: string }>();
    const previousPairs = new Set(
      history.results.map((pair) => pairKey(pair.email_a, pair.email_b)),
    );
    const lastUnmatchedByEmail = new Map(
      users.results.map((row) => [row.email, row.last_unmatched_at]),
    );
    const matching = createPairing(emails, previousPairs, lastUnmatchedByEmail);
    unmatchedEmail = matching.unmatched;
    const now = new Date().toISOString();
    const statements = [
      env.DB.prepare(
        "INSERT INTO pairing_runs (month, status, created_at, unmatched_email) VALUES (?, 'sending', ?, ?)",
      ).bind(month, now, unmatchedEmail ?? null),
    ];
    for (const [emailA, emailB] of matching.pairs) {
      statements.push(
        env.DB.prepare("INSERT INTO pairings (month, email_a, email_b) VALUES (?, ?, ?)").bind(
          month,
          emailA,
          emailB,
        ),
      );
    }
    await env.DB.batch(statements);
  }

  const pairs = await env.DB.prepare(
    "SELECT email_a, email_b, sent_a, sent_b FROM pairings WHERE month = ?",
  ).bind(month).all<{ email_a: string; email_b: string; sent_a: number; sent_b: number }>();

  for (const pair of pairs.results) {
    if (pair.sent_a && pair.sent_b) continue;
    await sendPairEmail(env, pair.email_a, pair.email_b, month);
    await env.DB.prepare(
      "UPDATE pairings SET sent_a = 1, sent_b = 1 WHERE month = ? AND email_a = ? AND email_b = ?",
    ).bind(month, pair.email_a, pair.email_b).run();
  }

  if (unmatchedEmail && !unmatchedSent) {
    await sendUnmatchedEmail(env, unmatchedEmail, month);
    await env.DB.prepare("UPDATE pairing_runs SET unmatched_sent = 1 WHERE month = ?")
      .bind(month).run();
    unmatchedSent = 1;
  }

  const now = new Date().toISOString();
  const completionStatements = [
    env.DB.prepare("UPDATE pairing_runs SET status = 'completed', completed_at = ? WHERE month = ?").bind(now, month),
    env.DB.prepare(
      `UPDATE users SET last_paired_at = ?, updated_at = ?
       WHERE email IN (
         SELECT email_a FROM pairings WHERE month = ?
         UNION SELECT email_b FROM pairings WHERE month = ?
       )`,
    ).bind(now, now, month, month),
    env.DB.prepare("DELETE FROM verification_tokens WHERE expires_at <= ?").bind(now),
    env.DB.prepare("DELETE FROM verification_requests WHERE created_at < ?").bind(
      new Date(date.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    ),
  ];
  if (unmatchedEmail) {
    completionStatements.push(
      env.DB.prepare("UPDATE users SET last_unmatched_at = ?, updated_at = ? WHERE email = ?")
        .bind(now, now, unmatchedEmail),
    );
  }
  await env.DB.batch(completionStatements);
}

async function sendPairEmail(env: Env, emailA: string, emailB: string, month: string) {
  const label = new Date(`${month}-02T00:00:00Z`).toLocaleDateString("en-US", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });
  const subject = `Your WeBairPair match for ${label}`;
  const text = `You've been paired for ${label}:\n\n${emailA}\n${emailB}\n\nReply all to introduce yourselves and find a time for a 1:1 chat. Have fun!`;
  const html = emailLayout(
    subject,
    `<p>You've been paired this month:</p><p><strong>${escapeHtml(emailA)}</strong><br><strong>${escapeHtml(emailB)}</strong></p><p>Reply all to introduce yourselves and find a time for a 1:1 chat. Have fun!</p>`,
  );
  await sendEmail(env, { to: [emailA, emailB], subject, text, html });
}

async function sendUnmatchedEmail(env: Env, recipient: string, month: string) {
  const label = new Date(`${month}-02T00:00:00Z`).toLocaleDateString("en-US", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });
  const subject = `A quick WeBairPair update for ${label}`;
  const text = `We had an odd number of participants this month, so we couldn't make a 1:1 match for you. You're still opted in, and we'll prioritize leaving someone else unmatched next month.`;
  const html = emailLayout(
    subject,
    `<p>We had an odd number of participants this month, so we couldn't make a 1:1 match for you.</p><p>You're still opted in, and we'll prioritize leaving someone else unmatched next month.</p>`,
  );
  await sendEmail(env, { to: [recipient], subject, text, html });
}

interface EmailMessage {
  to: string[];
  subject: string;
  text: string;
  html: string;
}

async function sendEmail(env: Env, message: EmailMessage): Promise<void> {
  if (!hasSesCredentials(env)) {
    if (env.ENVIRONMENT === "development") {
      console.log(`[email skipped] ${message.subject} -> ${message.to.join(", ")}`);
      return;
    }
    throw new Error("SES credentials are not configured.");
  }

  const region = env.AWS_REGION;
  const host = `email.${region}.amazonaws.com`;
  const endpoint = `https://${host}/v2/email/outbound-emails`;
  const payload = JSON.stringify({
    FromEmailAddress: env.SES_FROM_EMAIL,
    Destination: { ToAddresses: message.to },
    Content: {
      Simple: {
        Subject: { Data: message.subject, Charset: "UTF-8" },
        Body: {
          Text: { Data: message.text, Charset: "UTF-8" },
          Html: { Data: message.html, Charset: "UTF-8" },
        },
      },
    },
  });
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(payload);
  const canonicalHeaders = `content-type:application/json\nhost:${host}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "content-type;host;x-amz-date";
  const canonicalRequest = `POST\n/v2/email/outbound-emails\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const scope = `${dateStamp}/${region}/ses/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256Hex(canonicalRequest)}`;
  const signingKey = await getSignatureKey(env.AWS_SECRET_ACCESS_KEY, dateStamp, region, "ses");
  const signature = toHex(await hmac(signingKey, stringToSign));
  const authorization = `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-amz-date": amzDate,
      authorization,
    },
    body: payload,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`SES rejected email (${response.status}): ${detail}`);
  }
}

function hasSesCredentials(env: Env): env is Env & { AWS_ACCESS_KEY_ID: string; AWS_SECRET_ACCESS_KEY: string } {
  return Boolean(env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY);
}

async function getSignatureKey(secret: string, date: string, region: string, service: string): Promise<ArrayBuffer> {
  const kDate = await hmac(`AWS4${secret}`, date);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

async function hmac(key: string | ArrayBuffer, value: string): Promise<ArrayBuffer> {
  const keyData = typeof key === "string" ? encoder.encode(key).buffer as ArrayBuffer : key;
  const cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value));
}

async function sha256Hex(value: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

function toHex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function secureShuffle<T>(items: T[]): void {
  for (let i = items.length - 1; i > 0; i--) {
    const max = Math.floor(0x100000000 / (i + 1)) * (i + 1);
    let random: number;
    do random = crypto.getRandomValues(new Uint32Array(1))[0]; while (random >= max);
    const j = random % (i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
}

export function createPairing(
  emails: string[],
  previousPairs: ReadonlySet<string>,
  lastUnmatchedByEmail: ReadonlyMap<string, string | null> = new Map(),
): { pairs: Array<[string, string]>; unmatched?: string } {
  if (emails.length === 0) return { pairs: [] };

  const nodes = [...emails];
  const dummyIndex = nodes.length;
  if (nodes.length % 2 === 1) nodes.push("__unmatched__");

  const edges: Array<[number, number, number]> = [];
  const unmatchedPreference = new Map(
    [...emails]
      .sort((emailA, emailB) => compareUnmatchedPriority(
        lastUnmatchedByEmail.get(emailA),
        lastUnmatchedByEmail.get(emailB),
      ))
      .map((email, index) => [email, emails.length - index]),
  );
  const newPairWeight = emails.length + 2;
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const includesDummy = i === dummyIndex || j === dummyIndex;
      const isPrevious = !includesDummy && previousPairs.has(pairKey(nodes[i], nodes[j]));
      const realEmail = i === dummyIndex ? nodes[j] : nodes[i];
      const weight = includesDummy
        ? unmatchedPreference.get(realEmail) ?? 1
        : isPrevious ? 1 : newPairWeight;
      // One new-pair edge outweighs the full fairness range, so history remains primary.
      edges.push([i, j, weight]);
    }
  }

  const mates = blossom(edges, true);
  const pairs: Array<[string, string]> = [];
  let unmatched: string | undefined;
  for (let i = 0; i < mates.length; i++) {
    const mate = mates[i];
    if (mate < i) continue;
    if (i === dummyIndex) {
      unmatched = nodes[mate];
    } else if (mate === dummyIndex) {
      unmatched = nodes[i];
    } else {
      pairs.push([nodes[i], nodes[mate]]);
    }
  }
  return { pairs, unmatched };
}

function compareUnmatchedPriority(
  lastUnmatchedA: string | null | undefined,
  lastUnmatchedB: string | null | undefined,
): number {
  if (!lastUnmatchedA && !lastUnmatchedB) return 0;
  if (!lastUnmatchedA) return -1;
  if (!lastUnmatchedB) return 1;
  return lastUnmatchedA.localeCompare(lastUnmatchedB);
}

export function pairKey(emailA: string, emailB: string): string {
  return emailA < emailB ? `${emailA}\n${emailB}` : `${emailB}\n${emailA}`;
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function isBerkeleyEmail(value: string): boolean {
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@berkeley\.edu$/i.test(value);
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]!);
}

function emailLayout(title: string, content: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><style>body{font-family:Arial,sans-serif;color:#17324d;line-height:1.6}.wrap{max-width:560px;margin:32px auto;padding:24px}.button{display:inline-block;background:#FDB515;color:#111;text-decoration:none;font-weight:bold;padding:12px 18px}.muted{color:#657789;font-size:13px}</style></head><body><div class="wrap"><h1>${escapeHtml(title)}</h1>${content}</div></body></html>`;
}

function verificationPage(message: string, success: boolean): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WeBairPair</title><link rel="stylesheet" href="/styles.css"></head><body><main class="verify"><img src="/logo.png" alt="WeBairPair"><h1>${success ? "All set" : "Link unavailable"}</h1><p>${escapeHtml(message)}</p><a class="button-link" href="/">Back to WeBairPair</a></main></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8" } });
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: { "cache-control": "no-store" } });
}

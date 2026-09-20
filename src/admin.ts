export interface AdminEnv {
  DB: D1Database;
  APP_URL: string;
  ADMIN_PASSWORD?: string;
  ADMIN_SESSION_SECRET?: string;
}

type ConfiguredAdminEnv = AdminEnv & {
  ADMIN_PASSWORD: string;
  ADMIN_SESSION_SECRET: string;
};

const COOKIE_NAME = "__Host-webairpair_admin";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const LOGIN_WINDOW_MINUTES = 15;
const MAX_LOGIN_ATTEMPTS = 5;
const encoder = new TextEncoder();

export async function handleAdminRequest(
  request: Request,
  env: AdminEnv,
): Promise<Response> {
  const url = new URL(request.url);
  if (
    !env.ADMIN_PASSWORD ||
    env.ADMIN_PASSWORD.length < 16 ||
    !env.ADMIN_SESSION_SECRET ||
    env.ADMIN_SESSION_SECRET.length < 64
  ) {
    console.error("Admin secrets are not configured.");
    return adminHtml(
      messagePage(
        "Admin unavailable",
        "The admin dashboard is not configured.",
      ),
      503,
    );
  }
  const configuredEnv = env as ConfiguredAdminEnv;

  const authenticated = await hasValidSession(
    request,
    configuredEnv.ADMIN_SESSION_SECRET,
  );

  if (request.method === "GET" && url.pathname === "/admin") {
    return authenticated ? renderDashboard(env) : adminHtml(loginPage());
  }

  if (request.method === "POST" && url.pathname === "/admin/login") {
    if (!isAllowedAdminOrigin(request, env)) {
      return adminHtml(loginPage("Unable to sign in."), 403);
    }
    return login(request, configuredEnv);
  }

  if (request.method === "POST" && url.pathname === "/admin/logout") {
    if (!isAllowedAdminOrigin(request, env)) {
      return adminHtml(
        messagePage("Request denied", "Return to the dashboard and try again."),
        403,
      );
    }
    return redirectToAdmin(
      `${COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`,
    );
  }

  return adminHtml(
    messagePage("Not found", "That admin page does not exist."),
    404,
  );
}

async function login(request: Request, env: ConfiguredAdminEnv) {
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > 4096)
    return adminHtml(loginPage("Unable to sign in."), 413);

  const ip = request.headers.get("CF-Connecting-IP") ?? "local";
  const ipHash = await hmacHex(env.ADMIN_SESSION_SECRET, ip);
  const now = new Date();
  const windowStart = new Date(
    now.getTime() - LOGIN_WINDOW_MINUTES * 60 * 1000,
  ).toISOString();
  const attempts = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM admin_login_attempts WHERE ip_hash = ? AND attempted_at >= ?",
  )
    .bind(ipHash, windowStart)
    .first<{ count: number }>();

  if (Number(attempts?.count ?? 0) >= MAX_LOGIN_ATTEMPTS) {
    return adminHtml(
      loginPage("Too many attempts. Try again in 15 minutes."),
      429,
      {
        "retry-after": String(LOGIN_WINDOW_MINUTES * 60),
      },
    );
  }

  let suppliedPassword = "";
  try {
    const form = await request.formData();
    const value = form.get("password");
    suppliedPassword = typeof value === "string" ? value : "";
  } catch {
    return adminHtml(loginPage("Unable to sign in."), 400);
  }

  if (!(await passwordsMatch(suppliedPassword, env.ADMIN_PASSWORD))) {
    await env.DB.prepare(
      "INSERT INTO admin_login_attempts (ip_hash, attempted_at) VALUES (?, ?)",
    )
      .bind(ipHash, now.toISOString())
      .run();
    return adminHtml(loginPage("Incorrect password."), 401);
  }

  const token = await createAdminSessionToken(
    env.ADMIN_SESSION_SECRET,
    now.getTime(),
  );
  await env.DB.batch([
    env.DB.prepare("DELETE FROM admin_login_attempts WHERE ip_hash = ?").bind(
      ipHash,
    ),
    env.DB.prepare(
      "DELETE FROM admin_login_attempts WHERE attempted_at < ?",
    ).bind(new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString()),
  ]);
  return redirectToAdmin(
    `${COOKIE_NAME}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`,
  );
}

async function renderDashboard(env: AdminEnv): Promise<Response> {
  const [usersResult, countsResult] = await env.DB.batch([
    env.DB.prepare(
      "SELECT email, opted_in, created_at, updated_at FROM users ORDER BY created_at DESC, email ASC",
    ),
    env.DB.prepare(
      "SELECT COUNT(*) AS registered, COALESCE(SUM(opted_in), 0) AS opted_in FROM users",
    ),
  ]);
  const users = usersResult.results as Array<{
    email: string;
    opted_in: number;
    created_at: string;
    updated_at: string;
  }>;
  const counts = countsResult.results[0] as
    | { registered: number; opted_in: number }
    | undefined;
  const rows = users
    .map(
      (user) => `
    <tr>
      <td>${escapeHtml(user.email)}</td>
      <td><span class="status ${user.opted_in ? "in" : "out"}">${user.opted_in ? "Opted in" : "Opted out"}</span></td>
      <td><time datetime="${escapeHtml(user.created_at)}">${escapeHtml(formatDate(user.created_at))}</time></td>
      <td><time datetime="${escapeHtml(user.updated_at)}">${escapeHtml(formatDate(user.updated_at))}</time></td>
    </tr>`,
    )
    .join("");

  return adminHtml(
    `
    <header class="topbar">
      <a class="brand" href="/admin">WeBairPair</a>
      <form method="post" action="/admin/logout"><button class="quiet" type="submit">Sign out</button></form>
    </header>
    <main class="dashboard">
      <div class="heading"><div><p class="eyebrow">Admin</p><h1>Registrations</h1></div><p class="updated">Current database state</p></div>
      <section class="metrics" aria-label="Registration totals">
        <div><span>Registered</span><strong>${Number(counts?.registered ?? 0)}</strong></div>
        <div><span>Currently opted in</span><strong>${Number(counts?.opted_in ?? 0)}</strong></div>
      </section>
      <section class="table-section">
        <div class="table-heading"><h2>Email list</h2><span>${users.length} ${users.length === 1 ? "record" : "records"}</span></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Email</th><th>Status</th><th>Created</th><th>Updated</th></tr></thead>
            <tbody>${rows || '<tr><td class="empty" colspan="4">No registrations yet.</td></tr>'}</tbody>
          </table>
        </div>
      </section>
    </main>`,
    200,
    {},
    "WeBairPair Admin",
  );
}

export async function createAdminSessionToken(
  secret: string,
  nowMs = Date.now(),
): Promise<string> {
  const expires = Math.floor(nowMs / 1000) + SESSION_TTL_SECONDS;
  const nonce = randomHex(16);
  const payload = `${expires}.${nonce}`;
  return `${payload}.${await hmacHex(secret, payload)}`;
}

export async function validateAdminSessionToken(
  token: string,
  secret: string,
  nowMs = Date.now(),
): Promise<boolean> {
  const parts = token.split(".");
  if (
    parts.length !== 3 ||
    !/^\d+$/.test(parts[0]) ||
    !/^[a-f0-9]{32}$/.test(parts[1])
  )
    return false;
  const expires = Number(parts[0]);
  if (!Number.isSafeInteger(expires) || expires <= Math.floor(nowMs / 1000))
    return false;
  const payload = `${parts[0]}.${parts[1]}`;
  return constantTimeEqual(parts[2], await hmacHex(secret, payload));
}

export async function passwordsMatch(
  supplied: string,
  expected: string,
): Promise<boolean> {
  return constantTimeEqual(
    await sha256Hex(supplied),
    await sha256Hex(expected),
  );
}

export function isAllowedAdminOrigin(
  request: Request,
  env: Pick<AdminEnv, "APP_URL">,
): boolean {
  const origin = request.headers.get("origin");
  // Browsers can omit Origin (or send "null") under privacy policies.
  // Sec-Fetch-Site is browser-controlled and cannot be set by a cross-site page.
  if (!origin || origin === "null") {
    return request.headers.get("sec-fetch-site") === "same-origin";
  }
  let parsedOrigin: URL;
  let requestUrl: URL;
  try {
    parsedOrigin = new URL(origin);
    requestUrl = new URL(request.url);
  } catch {
    return false;
  }
  if (parsedOrigin.origin === requestUrl.origin) return true;
  if (isLoopbackHostname(requestUrl.hostname)) {
    return (
      (parsedOrigin.protocol === "http:" ||
        parsedOrigin.protocol === "https:") &&
      isLoopbackHostname(parsedOrigin.hostname)
    );
  }
  return parsedOrigin.origin === new URL(env.APP_URL).origin;
}

function isLoopbackHostname(hostname: string): boolean {
  return ["localhost", "127.0.0.1", "[::1]", "::1"].includes(hostname);
}

async function hasValidSession(
  request: Request,
  secret: string,
): Promise<boolean> {
  const cookie = request.headers.get("cookie") ?? "";
  const token = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE_NAME}=`))
    ?.slice(COOKIE_NAME.length + 1);
  return token ? validateAdminSessionToken(token, secret) : false;
}

function redirectToAdmin(cookie: string): Response {
  return new Response(null, {
    status: 303,
    headers: adminHeaders({ location: "/admin", "set-cookie": cookie }),
  });
}

function adminHtml(
  body: string,
  status = 200,
  extraHeaders: Record<string, string> = {},
  title = "WeBairPair Admin",
) {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>${adminStyles}</style></head><body>${body}</body></html>`,
    {
      status,
      headers: adminHeaders({
        "content-type": "text/html;charset=UTF-8",
        ...extraHeaders,
      }),
    },
  );
}

function adminHeaders(extra: Record<string, string>): Headers {
  return new Headers({
    "cache-control": "no-store, max-age=0",
    "content-security-policy":
      "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "referrer-policy": "same-origin",
    "x-robots-tag": "noindex, nofollow, noarchive",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    ...extra,
  });
}

function loginPage(error = ""): string {
  return `<main class="login"><a class="brand" href="/">WeBairPair</a><div><p class="eyebrow">Admin</p><h1>Sign in</h1><p class="muted">Enter the dashboard password to continue.</p>${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}<form method="post" action="/admin/login"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">Sign in</button></form></div></main>`;
}

function messagePage(title: string, message: string): string {
  return `<main class="login"><a class="brand" href="/">WeBairPair</a><div><h1>${escapeHtml(title)}</h1><p class="muted">${escapeHtml(message)}</p></div></main>`;
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "America/Los_Angeles",
    timeZoneName: "short",
  });
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>'"]/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&#39;",
        '"': "&quot;",
      })[character]!,
  );
}

function randomHex(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function hmacHex(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

function constantTimeEqual(left: string, right: string): boolean {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index++) {
    difference |=
      (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function toHex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

const adminStyles = `
:root{color-scheme:light;--ink:#102f4f;--blue:#003262;--gold:#fdb515;--paper:#f8fafb;--line:#cad5df;--muted:#5b6b7b;--red:#a52714}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--paper);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}.brand{color:var(--blue);font-weight:800;text-decoration:none}.login{width:min(420px,calc(100% - 40px));min-height:100vh;margin:auto;display:flex;flex-direction:column;justify-content:center;gap:48px;padding:40px 0}.login h1,.dashboard h1{margin:5px 0 10px;color:var(--blue);font-size:2.35rem;line-height:1.08}.eyebrow{margin:0;color:#6a7a89;font-size:.72rem;font-weight:800;text-transform:uppercase}.muted,.updated{color:var(--muted);line-height:1.55}.error{padding:10px 12px;border-left:3px solid var(--red);background:#fff2ef;color:var(--red);font-size:.9rem}form{margin-top:24px}label{display:block;margin-bottom:8px;color:var(--blue);font-size:.84rem;font-weight:750}input,button{min-height:46px;border:1px solid var(--line);border-radius:4px;font:inherit}input{width:100%;padding:0 13px;background:#fff;outline:none}input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,50,98,.12)}button{padding:0 18px;border-color:var(--gold);background:var(--gold);color:#13283d;font-weight:750;cursor:pointer}.login button{width:100%;margin-top:12px}.topbar{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 max(24px,calc((100% - 1120px)/2));border-bottom:1px solid var(--line);background:#fff}.topbar form{margin:0}.quiet{min-height:38px;border-color:var(--line);background:#fff;color:var(--blue);font-size:.86rem}.dashboard{width:min(1120px,calc(100% - 40px));margin:0 auto;padding:42px 0 64px}.heading,.table-heading{display:flex;align-items:end;justify-content:space-between;gap:20px}.updated{margin:0 0 7px;font-size:.86rem}.metrics{display:grid;grid-template-columns:repeat(2,minmax(0,220px));gap:12px;margin:28px 0 38px}.metrics div{padding:18px 20px;border:1px solid var(--line);border-radius:6px;background:#fff}.metrics span{display:block;color:var(--muted);font-size:.78rem;font-weight:700}.metrics strong{display:block;margin-top:5px;color:var(--blue);font-size:2rem}.table-section{border-top:1px solid var(--line);padding-top:24px}.table-heading h2{margin:0;color:var(--blue);font-size:1.15rem}.table-heading span{color:var(--muted);font-size:.8rem}.table-wrap{overflow-x:auto;margin-top:14px;border:1px solid var(--line);background:#fff}table{width:100%;border-collapse:collapse;font-size:.86rem;text-align:left}th,td{padding:13px 15px;border-bottom:1px solid #e4e9ee;white-space:nowrap}th{background:#f1f5f8;color:#536577;font-size:.7rem;text-transform:uppercase}tbody tr:last-child td{border-bottom:0}.status{font-size:.74rem;font-weight:750}.status.in{color:#16734b}.status.out{color:#6f7780}.empty{text-align:center;color:var(--muted);padding:38px}@media(max-width:560px){.heading{display:block}.updated{margin-top:8px}.metrics{grid-template-columns:1fr 1fr}.topbar{padding:0 20px}.dashboard{padding-top:30px}}`;

// Neighbourhood Watch — Worker backend
// Routes (mounted under /api — adjust in wrangler.toml route config if needed):
//   GET  /api/reports                    -> approved reports (public)
//   POST /api/reports                    -> submit a new report (status: pending)
//   POST /api/reports/image-upload       -> upload a photo to B2, returns { image_key }
//   GET  /api/reports/:id/image          -> proxies the image for an APPROVED report
//
//   [Admin — all require Authorization: Bearer <ADMIN_KEY>]
//   GET  /api/admin/reports              -> pending reports queue
//   POST /api/admin/reports/:id/approve  -> atomically approve a pending report
//   POST /api/admin/reports/:id/reject   -> atomically reject (body: { reason })
//   GET  /api/admin/reports/:id/image    -> proxies image for any status (pending review)
//
// Required secrets (wrangler secret put ...):
//   B2_KEY_ID            — Backblaze application key ID
//   B2_APPLICATION_KEY   — Backblaze application key
//   B2_BUCKET_ID         — the private bucket's ID
//   B2_BUCKET_NAME       — the private bucket's name (non-secret, can go in wrangler.toml)
//   ADMIN_KEY            — shared passcode for the admin console
//
// D1 binding must be named DB in wrangler.toml (see gotcha #1 in the stack notes).

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*", // tighten to your Pages domain once it's stable
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

// ---------- Auth ----------

// Checks Authorization: Bearer header OR ?token= query param.
// The query-param path is only used for <img> src URLs where we can't set headers.
function requireAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const headerToken = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const url = new URL(request.url);
  const queryToken = url.searchParams.get("token") || "";
  const token = headerToken || queryToken;
  if (!token || token !== env.ADMIN_KEY) {
    return json({ error: "Unauthorized" }, 401);
  }
  return null; // null means "ok, continue"
}

// ---------- B2 native API helper (no npm deps — plain fetch + Web Crypto) ----------
// B2 auth tokens last ~24h. We cache in module scope so we don't re-authenticate
// on every request within the same Worker isolate.
let b2Cache = { authToken: null, apiUrl: null, downloadUrl: null, expiresAt: 0 };

async function b2Authorize(env) {
  if (b2Cache.authToken && Date.now() < b2Cache.expiresAt) return b2Cache;

  const basic = btoa(`${env.B2_KEY_ID}:${env.B2_APPLICATION_KEY}`);
  const res = await fetch("https://api.backblazeb2.com/b2api/v3/b2_authorize_account", {
    headers: { Authorization: `Basic ${basic}` },
  });
  if (!res.ok) throw new Error(`B2 authorize failed: ${res.status}`);
  const data = await res.json();

  b2Cache = {
    authToken: data.authorizationToken,
    apiUrl: data.apiInfo.storageApi.apiUrl,
    downloadUrl: data.apiInfo.storageApi.downloadUrl,
    expiresAt: Date.now() + 23 * 60 * 60 * 1000, // refresh an hour early
  };
  return b2Cache;
}

async function b2GetUploadUrl(env) {
  const { apiUrl, authToken } = await b2Authorize(env);
  const res = await fetch(`${apiUrl}/b2api/v3/b2_get_upload_url`, {
    method: "POST",
    headers: { Authorization: authToken, "Content-Type": "application/json" },
    body: JSON.stringify({ bucketId: env.B2_BUCKET_ID }),
  });
  if (!res.ok) throw new Error(`B2 get_upload_url failed: ${res.status}`);
  return res.json();
}

async function sha1Hex(buf) {
  const digest = await crypto.subtle.digest("SHA-1", buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function b2UploadImage(env, fileName, bytes, contentType) {
  const { uploadUrl, authorizationToken } = await b2GetUploadUrl(env);
  const sha1 = await sha1Hex(bytes);

  const res = await fetch(uploadUrl, {
    method: "POST",
    headers: {
      Authorization: authorizationToken,
      "X-Bz-File-Name": encodeURIComponent(fileName),
      "Content-Type": contentType || "b2/x-auto",
      "X-Bz-Content-Sha1": sha1,
      "Content-Length": bytes.byteLength.toString(),
    },
    body: bytes,
  });
  if (!res.ok) throw new Error(`B2 upload failed: ${res.status} ${await res.text()}`);
  return res.json(); // includes fileId, fileName
}

async function b2DownloadImage(env, fileName) {
  const { downloadUrl, authToken } = await b2Authorize(env);
  const url = `${downloadUrl}/file/${env.B2_BUCKET_NAME}/${encodeURIComponent(fileName)}`;
  const res = await fetch(url, { headers: { Authorization: authToken } });
  return res; // caller checks res.ok
}

// ---------- VAPID / Web Push ----------

function b64urlToBytes(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from([...bin].map(c => c.charCodeAt(0)));
}

async function buildVapidAuth(env, audience) {
  const privBytes = b64urlToBytes(env.VAPID_PRIVATE_KEY);
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    privBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const header  = { typ: 'JWT', alg: 'ES256' };
  const payload = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: 'mailto:admin@elysiumwatch.local',
  };

  const enc = v => btoa(JSON.stringify(v)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const unsigned = `${enc(header)}.${enc(payload)}`;

  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    cryptoKey,
    new TextEncoder().encode(unsigned)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `vapid t=${unsigned}.${sigB64}, k=${env.VAPID_PUBLIC_KEY}`;
}

async function sendPush(env, sub, payload) {
  const url       = new URL(sub.endpoint);
  const audience  = `${url.protocol}//${url.host}`;
  const vapidAuth = await buildVapidAuth(env, audience);

  const body = JSON.stringify(payload);
  const res  = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization':  vapidAuth,
      'Content-Type':   'application/json',
      'Content-Length': String(new TextEncoder().encode(body).length),
      'TTL':            '86400',
    },
    body,
  });

  if (res.ok) return true;
  if (res.status === 404 || res.status === 410) return false; // expired — delete it
  console.error(`Push failed ${res.status} for ${sub.endpoint}`);
  return true; // transient error — keep subscription
}

async function fanOutPush(env, db, report) {
  const { results } = await db.prepare(
    'SELECT id, endpoint, p256dh, auth FROM push_subscriptions'
  ).all();

  if (!results.length) return;

  const catLabels = {
    suspicious: 'Suspicious activity',
    fire:       'Fire',
    flood:      'Flood',
    electrical: 'Electrical fault',
    water:      'Water supply fault',
    other:      'Other',
  };

  const payload = {
    title:    'New report',
    body:     `${catLabels[report.category] || report.category} — tap to review`,
    category: report.category,
    url:      'https://elysiumwatch.pages.dev/admin/',
  };

  const staleIds = [];
  await Promise.all(results.map(async sub => {
    const ok = await sendPush(env, sub, payload);
    if (!ok) staleIds.push(sub.id);
  }));

  if (staleIds.length) {
    const placeholders = staleIds.map(() => '?').join(',');
    await db.prepare(`DELETE FROM push_subscriptions WHERE id IN (${placeholders})`)
      .bind(...staleIds).run();
  }
}

// ---------- Public route handlers ----------

async function handleGetReports(request, env) {
  const { results } = await env.DB.prepare(
    `SELECT id, lat, lng, category, ref_nr, incident_at, message, image_key, created_at
     FROM reports WHERE status = 'approved' ORDER BY created_at DESC LIMIT 500`
  ).all();

  return json(results);
}

async function handleCreateReport(request, env, ctx) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { lat, lng, category, ref_nr, incident_at, message, reporter_contact, image_key } = body;

  if (typeof lat !== "number" || typeof lng !== "number") {
    return json({ error: "lat/lng are required numbers" }, 400);
  }
  const validCategories = ["suspicious", "fire", "flood", "electrical", "water", "other"];
  if (!validCategories.includes(category)) {
    return json({ error: "Invalid category" }, 400);
  }
  if (typeof message !== "string" || message.trim().length === 0) {
    return json({ error: "message is required" }, 400);
  }
  if (message.length > 600) {
    return json({ error: "message too long" }, 400);
  }

  const result = await env.DB.prepare(
    `INSERT INTO reports (lat, lng, category, ref_nr, incident_at, message, image_key, reporter_contact, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`
  ).bind(
    lat, lng, category,
    ref_nr || null,
    incident_at || null,
    message.trim(),
    image_key || null,
    reporter_contact || null
  ).run();

  const newId = result.meta.last_row_id;

  // Fire-and-forget push fan-out — doesn't block the resident's response
  ctx.waitUntil(fanOutPush(env, env.DB, { id: newId, category }));

  return json({ id: newId, status: "pending" }, 201);
}

async function handleImageUpload(request, env) {
  const formData = await request.formData();
  const file = formData.get("image");
  if (!file || typeof file === "string") {
    return json({ error: "No image file provided" }, 400);
  }
  if (file.size > 8 * 1024 * 1024) {
    return json({ error: "Image too large (max 8MB)" }, 400);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const ext = (file.name.split(".").pop() || "jpg").toLowerCase().replace(/[^a-z0-9]/g, "");
  const fileName = `reports/${Date.now()}-${crypto.randomUUID()}.${ext}`;

  const result = await b2UploadImage(env, fileName, bytes, file.type);
  return json({ image_key: result.fileName });
}

async function handleGetImage(request, env, reportId) {
  const report = await env.DB.prepare(
    `SELECT image_key, status FROM reports WHERE id = ?`
  ).bind(reportId).first();

  if (!report || !report.image_key || report.status !== "approved") {
    return new Response("Not found", { status: 404, headers: CORS_HEADERS });
  }

  const b2Res = await b2DownloadImage(env, report.image_key);
  if (!b2Res.ok) return new Response("Not found", { status: 404, headers: CORS_HEADERS });

  return new Response(b2Res.body, {
    headers: {
      "Content-Type": b2Res.headers.get("Content-Type") || "image/jpeg",
      "Cache-Control": "public, max-age=3600",
      ...CORS_HEADERS,
    },
  });
}

// ---------- Admin route handlers ----------

async function handleAdminGetHistory(request, env) {
  const { results } = await env.DB.prepare(
    `SELECT id, lat, lng, category, ref_nr, incident_at, message, image_key,
            reporter_contact, status, rejection_reason, created_at, reviewed_at
     FROM reports WHERE status IN ('approved', 'rejected') ORDER BY reviewed_at DESC LIMIT 500`
  ).all();

  return json(results);
}

async function handleAdminGetReports(request, env) {
  const { results } = await env.DB.prepare(
    `SELECT id, lat, lng, category, ref_nr, incident_at, message, image_key,
            reporter_contact, status, created_at
     FROM reports WHERE status = 'pending' ORDER BY created_at ASC`
  ).all();

  return json(results);
}

async function handleAdminApprove(request, env, reportId) {
  // Works on pending (first review) and rejected (re-approve from history)
  const result = await env.DB.prepare(
    `UPDATE reports
     SET status = 'approved', rejection_reason = NULL, reviewed_at = datetime('now'), reviewed_by = 'admin'
     WHERE id = ? AND status != 'approved'`
  ).bind(reportId).run();

  if (result.meta.changes === 0) {
    return json({ error: "Report not found or already approved" }, 409);
  }
  return json({ id: reportId, status: "approved" });
}

async function handleAdminReject(request, env, reportId) {
  let body = {};
  try { body = await request.json(); } catch { /* reason is optional */ }

  const reason = (body.reason || "").trim().slice(0, 300) || null;

  // Works on pending (first review) and approved (un-approve from history)
  const result = await env.DB.prepare(
    `UPDATE reports
     SET status = 'rejected', rejection_reason = ?, reviewed_at = datetime('now'), reviewed_by = 'admin'
     WHERE id = ? AND status != 'rejected'`
  ).bind(reason, reportId).run();

  if (result.meta.changes === 0) {
    // Already rejected — allow updating the reason
    const update = await env.DB.prepare(
      `UPDATE reports SET rejection_reason = ?, reviewed_at = datetime('now')
       WHERE id = ? AND status = 'rejected'`
    ).bind(reason, reportId).run();
    if (update.meta.changes === 0) return json({ error: "Report not found" }, 404);
  }
  return json({ id: reportId, status: "rejected" });
}

// Proxies image for pending reports — same as public handleGetImage but skips status check
async function handleAdminGetImage(request, env, reportId) {
  const report = await env.DB.prepare(
    `SELECT image_key FROM reports WHERE id = ?`
  ).bind(reportId).first();

  if (!report || !report.image_key) {
    return new Response("Not found", { status: 404, headers: CORS_HEADERS });
  }

  const b2Res = await b2DownloadImage(env, report.image_key);
  if (!b2Res.ok) return new Response("Not found", { status: 404, headers: CORS_HEADERS });

  return new Response(b2Res.body, {
    headers: {
      "Content-Type": b2Res.headers.get("Content-Type") || "image/jpeg",
      "Cache-Control": "no-store", // admin previews — don't cache
      ...CORS_HEADERS,
    },
  });
}

// ---------- Router ----------
export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ---- Public routes ----
      if (path === "/api/reports" && request.method === "GET") {
        return await handleGetReports(request, env);
      }
      if (path === "/api/reports" && request.method === "POST") {
        return await handleCreateReport(request, env, ctx);
      }
      if (path === "/api/reports/image-upload" && request.method === "POST") {
        return await handleImageUpload(request, env);
      }
      const publicImageMatch = path.match(/^\/api\/reports\/(\d+)\/image$/);
      if (publicImageMatch && request.method === "GET") {
        return await handleGetImage(request, env, Number(publicImageMatch[1]));
      }

      // ---- Admin routes (all require ADMIN_KEY) ----
      if (path.startsWith("/api/admin/")) {
        const authError = requireAdmin(request, env);
        if (authError) return authError;

        if (path === "/api/admin/reports" && request.method === "GET") {
          return await handleAdminGetReports(request, env);
        }

        if (path === "/api/admin/reports/history" && request.method === "GET") {
          return await handleAdminGetHistory(request, env);
        }

        const approveMatch = path.match(/^\/api\/admin\/reports\/(\d+)\/approve$/);
        if (approveMatch && request.method === "POST") {
          return await handleAdminApprove(request, env, Number(approveMatch[1]));
        }

        const rejectMatch = path.match(/^\/api\/admin\/reports\/(\d+)\/reject$/);
        if (rejectMatch && request.method === "POST") {
          return await handleAdminReject(request, env, Number(rejectMatch[1]));
        }

        const adminImageMatch = path.match(/^\/api\/admin\/reports\/(\d+)\/image$/);
        if (adminImageMatch && request.method === "GET") {
          return await handleAdminGetImage(request, env, Number(adminImageMatch[1]));
        }

        if (path === "/api/admin/push-subscribe" && request.method === "POST") {
          const { endpoint, keys } = await request.json();
          if (!endpoint || !keys?.p256dh || !keys?.auth) {
            return json({ error: "Missing subscription fields" }, 400);
          }
          await env.DB.prepare(`
            INSERT INTO push_subscriptions (endpoint, p256dh, auth)
            VALUES (?, ?, ?)
            ON CONFLICT(endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth
          `).bind(endpoint, keys.p256dh, keys.auth).run();
          return json({ ok: true });
        }

        if (path === "/api/admin/push-unsubscribe" && request.method === "POST") {
          const { endpoint } = await request.json();
          if (!endpoint) return json({ error: "Missing endpoint" }, 400);
          await env.DB.prepare(
            "DELETE FROM push_subscriptions WHERE endpoint = ?"
          ).bind(endpoint).run();
          return json({ ok: true });
        }

        return json({ error: "Not found" }, 404);
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      console.error(err);
      return json({ error: "Internal error" }, 500);
    }
  },
};

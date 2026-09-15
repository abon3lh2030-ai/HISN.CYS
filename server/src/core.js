import { createServer } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { resolve4, resolve6, resolveCname, resolveMx, resolveNs, resolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

const MAX_BODY_BYTES = 12 * 1024 * 1024;
const MAX_MESSAGE_COUNT = 12;
const MAX_TEXT_LENGTH = 12_000;
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;
const rateBuckets = new Map();

const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};

function sendJSON(response, status, body) {
  response.writeHead(status, jsonHeaders);
  response.end(JSON.stringify(body));
}

function safeEqual(actual = "", expected = "") {
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}

function isAuthorized(request) {
  const configured = process.env.HISN_API_ACCESS_TOKEN ?? "";
  const actual = request.headers.authorization?.replace(/^Bearer\s+/i, "") ?? "";
  return configured.length >= 32 && safeEqual(actual, configured);
}

function isRateLimited(request) {
  const forwarded = request.headers["x-forwarded-for"]?.split(",")[0]?.trim();
  const key = forwarded || request.socket.remoteAddress || "unknown";
  const now = Date.now();
  const current = rateBuckets.get(key);
  if (!current || now - current.startedAt >= RATE_WINDOW_MS) {
    rateBuckets.set(key, { startedAt: now, count: 1 });
    return false;
  }
  current.count += 1;
  return current.count > RATE_LIMIT;
}

async function readJSON(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new RequestError(413, "Request is too large.", "payload_too_large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new RequestError(400, "Invalid JSON body.", "invalid_json");
  }
}

class RequestError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function validateChatRequest(body) {
  if (!body || !Array.isArray(body.messages) || body.messages.length === 0 || body.messages.length > MAX_MESSAGE_COUNT) {
    throw new RequestError(400, "A valid message history is required.", "invalid_messages");
  }
  const messages = body.messages.map((message) => {
    const role = message?.role === "assistant" ? "assistant" : message?.role === "user" ? "user" : null;
    const text = typeof message?.text === "string" ? message.text.trim() : "";
    if (!role || !text || text.length > MAX_TEXT_LENGTH) {
      throw new RequestError(400, "Message content is invalid.", "invalid_message");
    }
    return { role, text };
  });

  let image = null;
  if (body.image != null) {
    const mimeType = body.image?.mimeType;
    const data = body.image?.data;
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(mimeType) || typeof data !== "string" || data.length > 10_000_000) {
      throw new RequestError(400, "Image content is invalid.", "invalid_image");
    }
    image = { mimeType, data };
  }
  return { messages, image };
}

export function validateIPLookupRequest(body) {
  const ip = typeof body?.ip === "string" ? body.ip.trim() : "";
  if (!isIP(ip)) throw new RequestError(400, "Enter a valid IPv4 or IPv6 address.", "invalid_ip");
  return ip;
}

export function validateDNSLookupRequest(body) {
  let host = typeof body?.host === "string" ? body.host.trim().toLowerCase() : "";
  if (host.includes("://")) {
    try { host = new URL(host).hostname; }
    catch { throw new RequestError(400, "Enter a valid domain name.", "invalid_host"); }
  }
  host = host.replace(/\.$/, "");
  const valid = host.length > 0 && host.length <= 253 && host.split(".").every((label) =>
    label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  );
  if (!valid || isIP(host)) throw new RequestError(400, "Enter a valid domain name.", "invalid_host");
  return host;
}

export function buildGeminiPayload(input) {
  const contents = input.messages.map((message) => ({
    role: message.role === "assistant" ? "model" : "user",
    parts: [{ text: message.text }]
  }));
  if (input.image) contents.at(-1).parts.push({ inlineData: input.image });
  return {
    systemInstruction: {
      parts: [{
        text: "You are HISN, a concise and helpful bilingual Arabic/English assistant. For cybersecurity questions, prioritize safe verification steps and never claim certainty from a risk score. Clearly state limitations. Answer in the user's language. If an image is attached, analyze only what is visible and call out suspicious links, requests for money, credentials, OTP codes, impersonation, and urgency when relevant."
      }]
    },
    contents,
    generationConfig: { maxOutputTokens: 1200, temperature: 0.4 }
  };
}

async function callGemini(input) {
  const apiKey = process.env.GEMINI_API_KEY;
  const model = process.env.GEMINI_MODEL || "gemini-3.6-flash";
  if (!apiKey) throw new RequestError(503, "AI service is not configured.", "gemini_not_configured");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55_000);
  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify(buildGeminiPayload(input)),
      signal: controller.signal
    });
    if (!response.ok) {
      const providerError = await response.json().catch(() => ({}));
      const status = providerError.error?.status;
      const reason = providerError.error?.details?.find((detail) => typeof detail.reason === "string")?.reason;
      console.error("Gemini request rejected", response.status,
        /^[A-Z_]{1,64}$/.test(status || "") ? status : "unknown",
        /^[A-Z_]{1,64}$/.test(reason || "") ? reason : "unknown");
      const code = response.status === 429 ? "ai_rate_limited"
        : response.status === 404 ? "ai_model_unavailable"
        : [401, 403].includes(response.status) ? "ai_access_denied"
        : response.status === 400 ? "ai_invalid_configuration" : "ai_upstream_error";
      throw new RequestError(response.status === 429 ? 429 : 502, "AI service could not complete the request.", code);
    }
    const data = await response.json();
    const text = (data.candidates ?? [])
      .flatMap((candidate) => candidate.content?.parts ?? [])
      .map((part) => part.text ?? "")
      .join("\n")
      .trim();
    if (!text) throw new RequestError(502, "AI service returned an unreadable response.", "empty_ai_response");
    return { text, model };
  } catch (error) {
    if (error?.name === "AbortError") throw new RequestError(504, "AI service timed out.", "ai_timeout");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

export function buildOperation({ requestId, input, model, durationMs, status, outputLength = 0, errorCode = null, appVersion = null }) {
  return {
    request_id: requestId,
    operation_type: input.image ? "image_chat" : "text_chat",
    status,
    model,
    duration_ms: durationMs,
    input_character_count: input.messages.reduce((sum, message) => sum + message.text.length, 0),
    output_character_count: outputLength,
    has_image: Boolean(input.image),
    error_code: errorCode,
    app_version: appVersion
  };
}

async function saveOperation(operation) {
  const baseURL = process.env.SUPABASE_URL?.replace(/\/$/, "");
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!baseURL || !secretKey) return;
  try {
    const response = await fetch(`${baseURL}/rest/v1/ai_operations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: secretKey, Prefer: "return=minimal" },
      body: JSON.stringify(operation),
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) console.error("Supabase operation log failed", response.status);
  } catch (error) {
    console.error("Supabase operation log unavailable", error?.name ?? "Error");
  }
}

function buildToolOperation({ requestId, operationType, inputLength, outputLength = 0, durationMs, status, errorCode = null, appVersion = null }) {
  return {
    request_id: requestId,
    operation_type: operationType,
    status,
    model: "hisn-toolkit",
    duration_ms: durationMs,
    input_character_count: inputLength,
    output_character_count: outputLength,
    has_image: false,
    error_code: errorCode,
    app_version: appVersion
  };
}

async function callIPLookup(ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);
  try {
    const upstream = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {
      headers: { Accept: "application/json", "User-Agent": "HISN-Security-Toolkit/1.0" },
      signal: controller.signal
    });
    if (!upstream.ok) throw new RequestError(502, "IP intelligence is temporarily unavailable.", "ip_upstream_error");
    const data = await upstream.json();
    if (!data?.ip) throw new RequestError(404, "No information was found for this IP address.", "ip_not_found");
    const [latitude, longitude] = typeof data.loc === "string" ? data.loc.split(",").map(Number) : [null, null];
    return {
      ip: data.ip,
      country: data.country || null,
      city: data.city || null,
      region: data.region || null,
      postal: data.postal || null,
      timezone: data.timezone || null,
      organization: data.org || null,
      latitude: Number.isFinite(latitude) ? latitude : null,
      longitude: Number.isFinite(longitude) ? longitude : null
    };
  } catch (error) {
    if (error?.name === "AbortError") throw new RequestError(504, "IP intelligence timed out.", "ip_timeout");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function fulfilled(result) {
  return result.status === "fulfilled" ? result.value : [];
}

async function callDNSLookup(host) {
  const results = await Promise.allSettled([
    resolve4(host, { ttl: true }),
    resolve6(host, { ttl: true }),
    resolveCname(host),
    resolveMx(host),
    resolveNs(host),
    resolveTxt(host)
  ]);
  const records = [
    ...fulfilled(results[0]).map((record) => ({ type: "A", value: record.address, ttl: record.ttl ?? null })),
    ...fulfilled(results[1]).map((record) => ({ type: "AAAA", value: record.address, ttl: record.ttl ?? null })),
    ...fulfilled(results[2]).map((record) => ({ type: "CNAME", value: record, ttl: null })),
    ...fulfilled(results[3]).map((record) => ({ type: "MX", value: `${record.priority} ${record.exchange || "."}`, ttl: null })),
    ...fulfilled(results[4]).map((record) => ({ type: "NS", value: record, ttl: null })),
    ...fulfilled(results[5]).map((record) => ({ type: "TXT", value: record.join(""), ttl: null }))
  ].slice(0, 80);
  if (records.length === 0) throw new RequestError(404, "No DNS records were found for this domain.", "dns_not_found");
  return { host, records };
}

async function handleTool(request, response, operationType, validate, perform) {
  if (!isAuthorized(request)) return sendJSON(response, 401, { error: "Unauthorized request.", code: "unauthorized" });
  if (isRateLimited(request)) return sendJSON(response, 429, { error: "Too many requests. Try again shortly.", code: "rate_limited" });
  const requestId = randomUUID();
  const startedAt = Date.now();
  let inputLength = 0;
  try {
    const input = validate(await readJSON(request));
    inputLength = input.length;
    const result = await perform(input);
    const outputLength = JSON.stringify(result).length;
    await saveOperation(buildToolOperation({
      requestId,
      operationType,
      inputLength,
      outputLength,
      durationMs: Date.now() - startedAt,
      status: "succeeded",
      appVersion: request.headers["x-hisn-app-version"] ?? null
    }));
    return sendJSON(response, 200, result);
  } catch (error) {
    const known = error instanceof RequestError ? error : new RequestError(500, "Unexpected server error.", "internal_error");
    await saveOperation(buildToolOperation({
      requestId,
      operationType,
      inputLength,
      durationMs: Date.now() - startedAt,
      status: "failed",
      errorCode: known.code,
      appVersion: request.headers["x-hisn-app-version"] ?? null
    }));
    return sendJSON(response, known.status, { error: known.message, code: known.code, requestId });
  }
}

async function handleChat(request, response) {
  if (!isAuthorized(request)) return sendJSON(response, 401, { error: "Unauthorized request." });
  if (isRateLimited(request)) return sendJSON(response, 429, { error: "Too many requests. Try again shortly." });
  const requestId = randomUUID();
  const startedAt = Date.now();
  let input = { messages: [], image: null };
  try {
    input = validateChatRequest(await readJSON(request));
    const result = await callGemini(input);
    await saveOperation(buildOperation({
      requestId,
      input,
      model: result.model,
      durationMs: Date.now() - startedAt,
      status: "succeeded",
      outputLength: result.text.length,
      appVersion: request.headers["x-hisn-app-version"] ?? null
    }));
    return sendJSON(response, 200, { text: result.text, requestId });
  } catch (error) {
    const known = error instanceof RequestError ? error : new RequestError(500, "Unexpected server error.", "internal_error");
    await saveOperation(buildOperation({
      requestId,
      input,
      model: process.env.GEMINI_MODEL || "gemini-3.6-flash",
      durationMs: Date.now() - startedAt,
      status: "failed",
      errorCode: known.code,
      appVersion: request.headers["x-hisn-app-version"] ?? null
    }));
    return sendJSON(response, known.status, { error: known.message, code: known.code, requestId });
  }
}

export function createHISNServer() {
  return createServer(async (request, response) => {
    const url = new URL(request.url, "http://localhost");
    if (request.method === "GET" && url.pathname === "/health") {
      return sendJSON(response, 200, { status: "ok", service: "hisn-secure-api", version: "1" });
    }
    if (request.method === "POST" && url.pathname === "/v1/ai/chat") return handleChat(request, response);
    if (request.method === "POST" && url.pathname === "/v1/tools/ip-lookup") {
      return handleTool(request, response, "ip_lookup", validateIPLookupRequest, callIPLookup);
    }
    if (request.method === "POST" && url.pathname === "/v1/tools/dns-lookup") {
      return handleTool(request, response, "dns_lookup", validateDNSLookupRequest, callDNSLookup);
    }
    return sendJSON(response, 404, { error: "Not found." });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 10000);
  createHISNServer().listen(port, "0.0.0.0", () => console.log(`HISN secure API listening on ${port}`));
}

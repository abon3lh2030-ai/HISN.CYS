import test from "node:test";
import assert from "node:assert/strict";
import {
  buildGeminiPayload,
  buildOperation,
  validateChatRequest,
  validateDNSLookupRequest,
  validateIPLookupRequest
} from "../src/core.js";

test("validates text and image input", () => {
  const input = validateChatRequest({
    messages: [{ role: "user", text: "حلل الصورة" }],
    image: { mimeType: "image/jpeg", data: "AQID" }
  });
  const payload = buildGeminiPayload(input);
  assert.equal(payload.contents[0].role, "user");
  assert.deepEqual(payload.contents[0].parts[1].inlineData, input.image);
});

test("operation metadata never includes prompt or image bytes", () => {
  const input = validateChatRequest({ messages: [{ role: "user", text: "secret prompt" }] });
  const operation = buildOperation({ requestId: "request-id", input, model: "test-model", durationMs: 12, status: "succeeded", outputLength: 8 });
  const serialized = JSON.stringify(operation);
  assert.equal(operation.input_character_count, 13);
  assert.equal(serialized.includes("secret prompt"), false);
  assert.equal("image" in operation, false);
});

test("rejects unsupported image types", () => {
  assert.throws(
    () => validateChatRequest({ messages: [{ role: "user", text: "test" }], image: { mimeType: "image/svg+xml", data: "PHN2Zz4=" } }),
    /Image content is invalid/
  );
});

test("validates IP lookup input", () => {
  assert.equal(validateIPLookupRequest({ ip: "8.8.8.8" }), "8.8.8.8");
  assert.equal(validateIPLookupRequest({ ip: "2001:4860:4860::8888" }), "2001:4860:4860::8888");
  assert.throws(() => validateIPLookupRequest({ ip: "example.com" }), /valid IPv4 or IPv6/);
});

test("normalizes and validates DNS lookup input", () => {
  assert.equal(validateDNSLookupRequest({ host: "https://Example.COM/path" }), "example.com");
  assert.equal(validateDNSLookupRequest({ host: "sub.example.com." }), "sub.example.com");
  assert.throws(() => validateDNSLookupRequest({ host: "not a domain" }), /valid domain/);
});

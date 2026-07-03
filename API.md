# PhishGuard Backend API Documentation

**Base URL (local development):** `http://127.0.0.1:8000/api`
**Base URL (production):** `TBD — to be filled in once deployed`

**Maintained by:** Nawaf — Backend & Infrastructure
**Last updated:** July 3, 2026

---

## Overview

The PhishGuard backend exposes two core endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/scan` | `POST` | Submit a URL for phishing/malware analysis |
| `/v1/webhooks/threat-intel` | `POST` | Receive extracted threat entities from the AI Agent (internal, signed) |

All requests and responses use `application/json`. All timestamps are ISO 8601, UTC.

---

## Authentication

| Endpoint | Auth method |
|---|---|
| `POST /v1/scan` | None (public-facing, called by the mobile app) |
| `POST /v1/webhooks/threat-intel` | HMAC-SHA256 signature (internal service-to-service only) |

The webhook endpoint is **not** intended to be called directly by the mobile app or any public client. See [Webhook Security](#webhook-security) below.

---

## 1. `POST /v1/scan`

Submits a URL for scanning. Uses a SHA-256 hash of the normalized URL as a cache key with a 7-day TTL — if the URL was scanned within the last 7 days, the cached result is returned instantly instead of re-querying VirusTotal and Google Safe Browsing.

### Request

```
POST /api/v1/scan
Content-Type: application/json
```

**Body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | The URL to scan. Must be a valid URL, max 2048 characters. |

**Example:**
```json
{
  "url": "https://example.com"
}
```

### Response — `200 OK`

**Fresh scan (cache miss):**
```json
{
  "cached": false,
  "url": "https://example.com",
  "status": "safe",
  "scanned_at": "2026-07-03T11:50:15.670648Z",
  "expires_at": "2026-07-10T11:50:15.670648Z"
}
```

**Cached result (cache hit, within 7-day TTL):**
```json
{
  "cached": true,
  "url": "https://example.com",
  "status": "safe",
  "scanned_at": "2026-07-03T11:50:15.670648Z",
  "expires_at": "2026-07-10T11:50:15.670648Z"
}
```

### Response fields

| Field | Type | Description |
|---|---|---|
| `cached` | boolean | `true` if served from cache, `false` if freshly scanned |
| `url` | string | The normalized URL that was scanned |
| `status` | string | One of `safe`, `suspicious`, `malicious`, `pending` |
| `scanned_at` | string (ISO 8601) | When the scan was performed |
| `expires_at` | string (ISO 8601) | When this cached result expires (7 days after `scanned_at`) |

### Status values

| Status | Meaning |
|---|---|
| `safe` | No threats detected by VirusTotal or Google Safe Browsing |
| `suspicious` | VirusTotal flagged the URL as suspicious (non-zero suspicious count, zero malicious count) |
| `malicious` | Flagged as malicious by VirusTotal, matched in Google Safe Browsing, **or** later confirmed by the AI Agent via the webhook (e.g. IBAN/wallet extraction) |
| `pending` | Default state before a scan completes (not normally seen in a synchronous response) |

### Error responses

| Status | Cause |
|---|---|
| `422 Unprocessable Content` | `url` missing, invalid format, or exceeds 2048 characters |
| `500 Internal Server Error` | Upstream failure (VirusTotal/Google Safe Browsing unreachable or misconfigured) |

**Validation error example:**
```json
{
  "message": "The url field must be a valid URL.",
  "errors": {
    "url": ["The url field must be a valid URL."]
  }
}
```

### curl example

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

---

## 2. `POST /v1/webhooks/threat-intel`

**Internal endpoint.** Called by Mohammed's AI Agent after it performs deep scanning (headless browsing + LLM analysis) on a URL and extracts financial threat entities (IBANs, wallet addresses, payment gateway identifiers).

Inserting a `iban` or `wallet` entity automatically:
1. Stores the entity in `threat_intelligence`, linked to the originating `scanned_urls` row.
2. Updates that URL's `status` to `malicious`.
3. Fires an outgoing webhook to n8n so downstream systems (e.g. bank alerting) are notified in near real time.

### Request

```
POST /api/v1/webhooks/threat-intel
Content-Type: application/json
X-Signature: <hmac-sha256-hex-digest>
```

**Body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `scanned_url_id` | UUID | Yes | Must match an existing `id` in `scanned_urls` |
| `entities` | array | Yes | At least one entity object |
| `entities[].entity_type` | string | Yes | One of `iban`, `wallet`, `payment_gateway` |
| `entities[].entity_value` | string | Yes | The extracted value (e.g. the IBAN string) |
| `entities[].confidence` | number | No | Model confidence score, `0.00`–`1.00` |
| `entities[].source` | string | No | Extraction source label. Defaults to `ai_agent` if omitted. |

**Example:**
```json
{
  "scanned_url_id": "a5e2fc61-7bbf-4389-82b4-b5314dc572ed",
  "entities": [
    {
      "entity_type": "iban",
      "entity_value": "SA1234567890",
      "confidence": 0.95,
      "source": "ai_agent"
    }
  ]
}
```

### Response — `200 OK`

```json
{
  "status": "received",
  "inserted": 1
}
```

### Error responses

| Status | Cause |
|---|---|
| `401 Unauthorized` | Missing or invalid `X-Signature` header |
| `422 Unprocessable Content` | `scanned_url_id` is not a valid UUID, doesn't exist in `scanned_urls`, or `entities` fails validation |

---

## Webhook Security

The threat-intel webhook is protected with an **HMAC-SHA256** signature to ensure only trusted internal services (the AI Agent) can submit data.

### How to sign a request

1. Take the **raw JSON request body** (exact bytes, before any formatting).
2. Compute `HMAC-SHA256(body, WEBHOOK_SECRET)`.
3. Send the resulting hex digest in the `X-Signature` header.

The server recomputes the signature on its end and rejects the request with `401` if it doesn't match exactly (`hash_equals`, constant-time comparison — timing-attack safe).

The shared secret is not published in this document. Request it directly from Nawaf and store it in your service's environment configuration — never commit it to version control.

### Example (Python)

```python
import hmac
import hashlib
import json

secret = "shared-webhook-secret"  # from secure config, not hardcoded
body = json.dumps({
    "scanned_url_id": "a5e2fc61-7bbf-4389-82b4-b5314dc572ed",
    "entities": [
        {"entity_type": "iban", "entity_value": "SA1234567890", "confidence": 0.95}
    ]
})

signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-Signature": signature
}
```

### Example (Node.js)

```javascript
const crypto = require('crypto');

const secret = "shared-webhook-secret"; // from secure config, not hardcoded
const body = JSON.stringify({
  scanned_url_id: "a5e2fc61-7bbf-4389-82b4-b5314dc572ed",
  entities: [
    { entity_type: "iban", entity_value: "SA1234567890", confidence: 0.95 }
  ]
});

const signature = crypto.createHmac('sha256', secret).update(body).digest('hex');

const headers = {
  "Content-Type": "application/json",
  "X-Signature": signature
};
```

---

## Data Model Reference

### `scanned_urls`

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `url` | text | Normalized URL |
| `url_hash` | char(64) | SHA-256 hex digest of the normalized URL, unique, used as cache key |
| `status` | enum | `safe` \| `suspicious` \| `malicious` \| `pending` |
| `vt_result` | jsonb | Raw VirusTotal API response |
| `gsb_result` | jsonb | Raw Google Safe Browsing API response |
| `scanned_at` | timestamptz | When the scan was performed |
| `expires_at` | timestamptz | `scanned_at` + 7 days |
| `created_at` / `updated_at` | timestamptz | Standard timestamps |

### `threat_intelligence`

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `scanned_url_id` | UUID | Foreign key → `scanned_urls.id`, cascades on delete |
| `entity_type` | string | `iban` \| `wallet` \| `payment_gateway` |
| `entity_value` | text | The extracted value |
| `confidence` | decimal(3,2) | Nullable, model confidence score |
| `source` | string | Extraction source, e.g. `ai_agent` |
| `created_at` / `updated_at` | timestamptz | Standard timestamps |

---

## Rate Limits & Upstream Dependencies

| Service | Free-tier limit | Notes |
|---|---|---|
| VirusTotal | ~4 requests/minute | Applies to the underlying call inside `/v1/scan`; heavy testing may hit this limit |
| Google Safe Browsing | Generous default quota | Rarely a bottleneck in development |

If `/v1/scan` returns a `500` unexpectedly, check `storage/logs/laravel.log` first — most failures to date have been upstream connectivity/SSL issues rather than application logic.

---

## Changelog

| Date | Change |
|---|---|
| 2026-07-03 | Initial release: `/v1/scan` and `/v1/webhooks/threat-intel` |

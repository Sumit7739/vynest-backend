import { getFirebaseServiceAccount } from "./env";

const FIREBASE_JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

let cachedJwks = null;
let cachedJwksExpiresAt = 0;

export class AuthError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

function base64UrlDecodeToString(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  return atob(padded);
}

function base64UrlDecodeToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function parseJsonFromBase64Url(part, label) {
  try {
    return JSON.parse(base64UrlDecodeToString(part));
  } catch (_error) {
    throw new AuthError(401, `Invalid ${label}`);
  }
}

function parseBearerToken(request) {
  const authHeader = request.headers.get("authorization") || "";
  const [scheme, token] = authHeader.split(" ");

  if (!scheme || scheme.toLowerCase() !== "bearer" || !token) {
    throw new AuthError(401, "Missing bearer token");
  }

  return token;
}

function getFirebaseProjectId(env) {
  if (env.FIREBASE_PROJECT_ID) {
    return String(env.FIREBASE_PROJECT_ID).trim();
  }

  const serviceAccount = getFirebaseServiceAccount(env);
  return String(serviceAccount.project_id || "").trim();
}

function parseCacheMaxAgeSeconds(cacheControl) {
  const value = String(cacheControl || "");
  const match = value.match(/max-age=(\d+)/i);

  if (!match) {
    return 300;
  }

  return Number.parseInt(match[1], 10) || 300;
}

async function getFirebaseJwks() {
  const now = Date.now();

  if (cachedJwks && now < cachedJwksExpiresAt) {
    return cachedJwks;
  }

  const response = await fetch(FIREBASE_JWKS_URL, {
    method: "GET"
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new AuthError(503, `Unable to load auth keys: ${response.status} ${errorText}`);
  }

  const jwks = await response.json();
  const maxAgeSeconds = parseCacheMaxAgeSeconds(response.headers.get("cache-control"));

  cachedJwks = jwks;
  cachedJwksExpiresAt = now + maxAgeSeconds * 1000;

  return jwks;
}

async function verifyJwtSignature(token, header) {
  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new AuthError(401, "Invalid token format");
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const signatureBytes = base64UrlDecodeToBytes(parts[2]);

  const jwks = await getFirebaseJwks();
  const jwk = jwks?.keys?.find((key) => key.kid === header.kid);

  if (!jwk) {
    throw new AuthError(401, "Token signing key not found");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signatureBytes,
    new TextEncoder().encode(signingInput)
  );

  if (!valid) {
    throw new AuthError(401, "Invalid token signature");
  }
}

function validateTokenClaims(payload, projectId) {
  const now = Math.floor(Date.now() / 1000);
  const expectedIssuer = `https://securetoken.google.com/${projectId}`;

  if (payload.iss !== expectedIssuer) {
    throw new AuthError(401, "Invalid token issuer");
  }

  if (payload.aud !== projectId) {
    throw new AuthError(401, "Invalid token audience");
  }

  if (!payload.sub || typeof payload.sub !== "string" || payload.sub.length > 128) {
    throw new AuthError(401, "Invalid token subject");
  }

  if (!payload.exp || Number(payload.exp) <= now) {
    throw new AuthError(401, "Token expired");
  }

  if (!payload.iat || Number(payload.iat) > now + 300) {
    throw new AuthError(401, "Invalid token issue time");
  }
}

export async function requireAuthUser(request, env) {
  const token = parseBearerToken(request);
  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new AuthError(401, "Invalid token format");
  }

  const header = parseJsonFromBase64Url(parts[0], "token header");
  const payload = parseJsonFromBase64Url(parts[1], "token payload");
  const projectId = getFirebaseProjectId(env);

  if (!projectId) {
    throw new AuthError(500, "Missing Firebase project configuration");
  }

  if (header.alg !== "RS256" || !header.kid) {
    throw new AuthError(401, "Unsupported token algorithm");
  }

  await verifyJwtSignature(token, header);
  validateTokenClaims(payload, projectId);

  return {
    uid: payload.sub,
    email: payload.email || null,
    emailVerified: Boolean(payload.email_verified)
  };
}

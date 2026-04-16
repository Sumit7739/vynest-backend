import { getFirebaseServiceAccount } from "./env";

const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const OAUTH_SCOPE = "https://www.googleapis.com/auth/datastore";

let cachedAccessToken = null;
let cachedAccessTokenExpiresAt = 0;

function base64UrlEncode(input) {
  let raw;

  if (typeof input === "string") {
    raw = new TextEncoder().encode(input);
  } else {
    raw = new Uint8Array(input);
  }

  let binary = "";
  for (const byte of raw) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pemToArrayBuffer(pem) {
  const cleanPem = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");

  const decoded = atob(cleanPem);
  const bytes = new Uint8Array(decoded.length);

  for (let i = 0; i < decoded.length; i += 1) {
    bytes[i] = decoded.charCodeAt(i);
  }

  return bytes.buffer;
}

async function signJwt(privateKeyPem, payload) {
  const header = { alg: "RS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKeyPem),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64UrlEncode(signatureBuffer);
  return `${signingInput}.${encodedSignature}`;
}

export async function getGoogleAccessToken(env) {
  const now = Date.now();

  if (cachedAccessToken && now < cachedAccessTokenExpiresAt - 60_000) {
    return cachedAccessToken;
  }

  const serviceAccount = getFirebaseServiceAccount(env);

  const iat = Math.floor(now / 1000);
  const exp = iat + 3600;

  const jwtPayload = {
    iss: serviceAccount.client_email,
    scope: OAUTH_SCOPE,
    aud: TOKEN_ENDPOINT,
    iat,
    exp
  };

  const assertion = await signJwt(serviceAccount.private_key, jwtPayload);

  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion
  });

  const response = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch Google access token: ${response.status} ${errorText}`);
  }

  const tokenData = await response.json();
  cachedAccessToken = tokenData.access_token;
  cachedAccessTokenExpiresAt = now + (Number(tokenData.expires_in) || 3600) * 1000;

  return cachedAccessToken;
}

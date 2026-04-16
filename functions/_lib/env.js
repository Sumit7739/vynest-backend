const REQUIRED_ENV_KEYS = [
  "CASHFREE_CLIENT_ID",
  "CASHFREE_CLIENT_SECRET",
  "FIREBASE_SERVICE_ACCOUNT_JSON"
];

export function getRequiredEnv(env, key) {
  const value = env[key];

  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }

  return value;
}

export function validateRequiredEnv(env) {
  for (const key of REQUIRED_ENV_KEYS) {
    getRequiredEnv(env, key);
  }
}

export function getFirebaseServiceAccount(env) {
  const rawValue = getRequiredEnv(env, "FIREBASE_SERVICE_ACCOUNT_JSON");

  try {
    return JSON.parse(rawValue);
  } catch (error) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
  }
}

export function getBackendCorsOrigin(env) {
  return env.CORS_ORIGIN || "*";
}

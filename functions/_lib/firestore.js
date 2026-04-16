import { getFirebaseServiceAccount } from "./env";
import { getGoogleAccessToken } from "./googleAuth";

function toFirestoreValue(value) {
  if (value === null || value === undefined) {
    return { nullValue: null };
  }

  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map((item) => toFirestoreValue(item))
      }
    };
  }

  if (value instanceof Date) {
    return { timestampValue: value.toISOString() };
  }

  if (typeof value === "object") {
    return {
      mapValue: {
        fields: toFirestoreFields(value)
      }
    };
  }

  if (typeof value === "boolean") {
    return { booleanValue: value };
  }

  if (typeof value === "number") {
    if (Number.isInteger(value)) {
      return { integerValue: String(value) };
    }

    return { doubleValue: value };
  }

  return { stringValue: String(value) };
}

function fromFirestoreValue(value) {
  if (!value || typeof value !== "object") {
    return null;
  }

  if ("nullValue" in value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("timestampValue" in value) return value.timestampValue;

  if ("arrayValue" in value) {
    const items = value.arrayValue?.values || [];
    return items.map((item) => fromFirestoreValue(item));
  }

  if ("mapValue" in value) {
    const output = {};
    const fields = value.mapValue?.fields || {};

    for (const [key, mapFieldValue] of Object.entries(fields)) {
      output[key] = fromFirestoreValue(mapFieldValue);
    }

    return output;
  }

  return null;
}

export function toFirestoreFields(payload) {
  const fields = {};

  for (const [key, value] of Object.entries(payload)) {
    fields[key] = toFirestoreValue(value);
  }

  return fields;
}

export function fromFirestoreDocument(document) {
  const nameParts = (document.name || "").split("/");
  const id = nameParts[nameParts.length - 1] || null;
  const fields = document.fields || {};
  const parsed = {};

  for (const [key, value] of Object.entries(fields)) {
    parsed[key] = fromFirestoreValue(value);
  }

  return {
    id,
    ...parsed
  };
}

function getFirestoreBaseUrl(env) {
  const serviceAccount = getFirebaseServiceAccount(env);
  const projectId = serviceAccount.project_id;

  return `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;
}

async function firestoreRequest(env, path, init = {}) {
  const accessToken = await getGoogleAccessToken(env);
  const baseUrl = getFirestoreBaseUrl(env);

  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
      ...(init.headers || {})
    }
  });

  return response;
}

export async function getDocument(env, collectionName, documentId) {
  const response = await firestoreRequest(env, `/${collectionName}/${documentId}`, {
    method: "GET"
  });

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Firestore getDocument failed: ${response.status} ${errorText}`);
  }

  const document = await response.json();
  return fromFirestoreDocument(document);
}

export async function setDocument(env, collectionName, documentId, payload) {
  const response = await firestoreRequest(env, `/${collectionName}/${documentId}`, {
    method: "PATCH",
    body: JSON.stringify({
      fields: toFirestoreFields(payload)
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Firestore setDocument failed: ${response.status} ${errorText}`);
  }

  const document = await response.json();
  return fromFirestoreDocument(document);
}

export async function updateDocument(env, collectionName, documentId, payload) {
  const fieldPaths = Object.keys(payload)
    .map((key) => `updateMask.fieldPaths=${encodeURIComponent(key)}`)
    .join("&");

  const queryString = fieldPaths ? `?${fieldPaths}` : "";

  const response = await firestoreRequest(
    env,
    `/${collectionName}/${documentId}${queryString}`,
    {
      method: "PATCH",
      body: JSON.stringify({
        fields: toFirestoreFields(payload)
      })
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Firestore updateDocument failed: ${response.status} ${errorText}`);
  }

  const document = await response.json();
  return fromFirestoreDocument(document);
}

export async function listDocuments(env, collectionName, pageSize = 1) {
  const response = await firestoreRequest(
    env,
    `/${collectionName}?pageSize=${encodeURIComponent(String(pageSize))}`,
    {
      method: "GET"
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Firestore listDocuments failed: ${response.status} ${errorText}`);
  }

  const payload = await response.json();
  const docs = payload.documents || [];

  return docs.map((doc) => fromFirestoreDocument(doc));
}

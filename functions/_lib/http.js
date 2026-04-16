import { getBackendCorsOrigin } from "./env";

export function jsonResponse(env, status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": getBackendCorsOrigin(env),
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type"
    }
  });
}

export function optionsResponse(env) {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": getBackendCorsOrigin(env),
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type"
    }
  });
}

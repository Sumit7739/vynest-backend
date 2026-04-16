import { jsonResponse } from "./_lib/http";

export const onRequestGet = async ({ env }) => {
  return jsonResponse(env, 200, {
    ok: true,
    service: "vynest-backend",
    runtime: "cloudflare-pages-functions"
  });
};

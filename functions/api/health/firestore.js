import { listDocuments } from "../../_lib/firestore";
import { jsonResponse } from "../../_lib/http";

export const onRequestGet = async ({ env }) => {
  try {
    await listDocuments(env, "rooms", 1);

    return jsonResponse(env, 200, {
      ok: true,
      service: "firestore",
      status: "connected"
    });
  } catch (error) {
    console.error("Firestore health check failed", error);

    return jsonResponse(env, 503, {
      ok: false,
      service: "firestore",
      status: "unavailable",
      errorCode: error?.message || "UNKNOWN"
    });
  }
};

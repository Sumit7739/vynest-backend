import { onRequestGet as rootGet } from "./functions/index.js";
import {
  onRequestOptions as createOrderOptions,
  onRequestPost as createOrderPost
} from "./functions/api/create-order.js";
import {
  onRequestOptions as webhookOptions,
  onRequestPost as webhookPost
} from "./functions/api/webhook.js";
import { onRequestGet as firestoreHealthGet } from "./functions/api/health/firestore.js";
import { onRequestGet as verifyPaymentGet } from "./functions/api/verify-payment/[orderId].js";
import { jsonResponse } from "./functions/_lib/http.js";

function normalizePath(pathname) {
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }

  return pathname;
}

function getOrderIdFromPath(pathname) {
  const basePaths = ["/verify-payment/", "/api/verify-payment/"];

  for (const basePath of basePaths) {
    if (pathname.startsWith(basePath)) {
      const orderId = pathname.slice(basePath.length);
      return orderId ? decodeURIComponent(orderId) : "";
    }
  }

  return "";
}

export default {
  async fetch(request, env, ctx) {
    const method = request.method.toUpperCase();
    const pathname = normalizePath(new URL(request.url).pathname);
    const commonContext = { request, env, waitUntil: ctx.waitUntil.bind(ctx) };

    if (pathname === "/" && method === "GET") {
      return rootGet(commonContext);
    }

    if ((pathname === "/create-order" || pathname === "/api/create-order") && method === "OPTIONS") {
      return createOrderOptions(commonContext);
    }

    if ((pathname === "/create-order" || pathname === "/api/create-order") && method === "POST") {
      return createOrderPost(commonContext);
    }

    if ((pathname === "/webhook" || pathname === "/api/webhook") && method === "OPTIONS") {
      return webhookOptions(commonContext);
    }

    if ((pathname === "/webhook" || pathname === "/api/webhook") && method === "POST") {
      return webhookPost(commonContext);
    }

    if ((pathname === "/health/firestore" || pathname === "/api/health/firestore") && method === "GET") {
      return firestoreHealthGet(commonContext);
    }

    if (method === "GET") {
      const orderId = getOrderIdFromPath(pathname);

      if (orderId) {
        return verifyPaymentGet({
          ...commonContext,
          params: { orderId }
        });
      }
    }

    return jsonResponse(env, 404, {
      ok: false,
      error: "Not found"
    });
  }
};

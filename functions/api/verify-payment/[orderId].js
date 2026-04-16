import { getDocument } from "../../_lib/firestore";
import { jsonResponse } from "../../_lib/http";

export const onRequestGet = async ({ env, params }) => {
  try {
    const orderId = params.orderId;
    const order = await getDocument(env, "orders", orderId);

    if (!order) {
      return jsonResponse(env, 404, { success: false, status: "NOT_FOUND" });
    }

    if (order.status === "PAID") {
      return jsonResponse(env, 200, { success: true, status: "PAID" });
    }

    return jsonResponse(env, 200, { success: false, status: order.status || "PENDING" });
  } catch (error) {
    console.error(error);
    return jsonResponse(env, 500, { success: false, status: "ERROR" });
  }
};

import { getRequiredEnv, validateRequiredEnv } from "../_lib/env";
import { getDocument, setDocument } from "../_lib/firestore";
import { jsonResponse, optionsResponse } from "../_lib/http";
import { isValidDateInput, resolveBookingAmount } from "../_lib/payment";

export const onRequestOptions = async ({ env }) => optionsResponse(env);

const normalizeCustomerPhone = (value) => {
  const digits = String(value || "").replace(/\D/g, "");

  if (digits.length === 10) {
    return digits;
  }

  if (digits.length === 12 && digits.startsWith("91")) {
    return digits.slice(2);
  }

  return "9999999999";
};

export const onRequestPost = async ({ request, env }) => {
  try {
    validateRequiredEnv(env);

    const payload = await request.json();
    const { userId, roomId, moveInDate, occupancyIndex } = payload || {};
    const parsedOccupancyIndex = Number.parseInt(occupancyIndex, 10);

    if (
      !payload ||
      typeof payload !== "object" ||
      typeof userId !== "string" ||
      !userId.trim() ||
      typeof roomId !== "string" ||
      !roomId.trim() ||
      !isValidDateInput(moveInDate) ||
      Number.isNaN(parsedOccupancyIndex) ||
      parsedOccupancyIndex < 0
    ) {
      return jsonResponse(env, 400, { error: "Missing fields" });
    }

    const room = await getDocument(env, "rooms", roomId);

    if (!room) {
      return jsonResponse(env, 404, { error: "Room not found" });
    }

    const selectedRoom = room.roomDetails?.[parsedOccupancyIndex];

    if (!selectedRoom) {
      return jsonResponse(env, 400, { error: "Invalid room selection" });
    }

    const amountDecision = resolveBookingAmount({ room, selectedRoom, env });
    const amount = amountDecision.amount;

    if (!amount) {
      return jsonResponse(env, 400, { error: "Unable to calculate booking fee" });
    }

    const orderId = `order_${Date.now()}`;
    const requestOrigin = new URL(request.url).origin;
    const frontendBaseUrl = (env.FRONTEND_BASE_URL || "https://vynest.in").replace(/\/$/, "");
    const webhookUrl = `${requestOrigin}/webhook`;
    const returnUrl = `${frontendBaseUrl}/pages/payment-success.html?order_id=${encodeURIComponent(orderId)}`;

    const cashfreeResponse = await fetch("https://api.cashfree.com/pg/orders", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-client-id": getRequiredEnv(env, "CASHFREE_CLIENT_ID"),
        "x-client-secret": getRequiredEnv(env, "CASHFREE_CLIENT_SECRET"),
        "x-api-version": "2022-09-01"
      },
      body: JSON.stringify({
        order_id: orderId,
        order_amount: amount,
        order_currency: "INR",
        customer_details: {
          customer_id: userId,
          customer_phone: normalizeCustomerPhone(payload?.customerPhone)
        },
        order_meta: {
          return_url: returnUrl,
          notify_url: webhookUrl
        }
      })
    });

    if (!cashfreeResponse.ok) {
      const errorBody = await cashfreeResponse.text();
      console.error("Cashfree create order failed", errorBody);

      let errorMessage = "Cashfree order creation failed";

      try {
        const parsed = JSON.parse(errorBody);
        errorMessage =
          parsed?.message ||
          parsed?.error_description ||
          parsed?.type ||
          errorMessage;
      } catch (_ignored) {
        // Keep default message when response is not JSON.
      }

      return jsonResponse(env, 502, { error: errorMessage });
    }

    const cashfreeData = await cashfreeResponse.json();

    await setDocument(env, "orders", orderId, {
      userId,
      roomId,
      amount,
      amountSource: amountDecision.source,
      formCode: amountDecision.formCode || null,
      moveInDate,
      roomPrice: selectedRoom.fee,
      occupancyIndex: String(parsedOccupancyIndex),
      status: "PENDING"
    });

    return jsonResponse(env, 200, {
      payment_session_id: cashfreeData.payment_session_id
    });
  } catch (error) {
    console.error(error);
    return jsonResponse(env, 500, { error: "Order failed" });
  }
};

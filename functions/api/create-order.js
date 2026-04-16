import { getRequiredEnv, validateRequiredEnv } from "../_lib/env";
import { getDocument, setDocument } from "../_lib/firestore";
import { jsonResponse, optionsResponse } from "../_lib/http";
import { calculateBookingFee, isValidDateInput } from "../_lib/payment";

export const onRequestOptions = async ({ env }) => optionsResponse(env);

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

    const amount = calculateBookingFee(room.propertyType, selectedRoom.type);

    if (!amount) {
      return jsonResponse(env, 400, { error: "Unable to calculate booking fee" });
    }

    const orderId = `order_${Date.now()}`;

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
          customer_phone: "9999999999"
        }
      })
    });

    if (!cashfreeResponse.ok) {
      const errorBody = await cashfreeResponse.text();
      console.error("Cashfree create order failed", errorBody);
      return jsonResponse(env, 502, { error: "Cashfree order creation failed" });
    }

    const cashfreeData = await cashfreeResponse.json();

    await setDocument(env, "orders", orderId, {
      userId,
      roomId,
      amount,
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

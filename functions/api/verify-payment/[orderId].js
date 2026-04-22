import { getDocument, setDocument, updateDocument } from "../../_lib/firestore";
import { getRequiredEnv } from "../../_lib/env";
import { jsonResponse } from "../../_lib/http";

const PAID_STATUS = "PAID";

async function isCashfreeOrderPaid(env, orderId) {
  const response = await fetch(
    `https://api.cashfree.com/pg/orders/${encodeURIComponent(orderId)}`,
    {
      method: "GET",
      headers: {
        "x-client-id": getRequiredEnv(env, "CASHFREE_CLIENT_ID"),
        "x-client-secret": getRequiredEnv(env, "CASHFREE_CLIENT_SECRET"),
        "x-api-version": "2022-09-01"
      }
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    console.error("Cashfree verify order failed", errorText);
    return false;
  }

  const payload = await response.json();
  const status = String(payload?.order_status || payload?.orderStatus || "").toUpperCase();
  return status === PAID_STATUS;
}

async function ensureBookingForOrder(env, orderId, order) {
  const existingBooking = await getDocument(env, "bookings", orderId);

  if (existingBooking) {
    return true;
  }

  const room = await getDocument(env, "rooms", order.roomId);

  if (!room) {
    return false;
  }

  const selectedRoom = room.roomDetails?.[Number(order.occupancyIndex)] || {};

  await setDocument(env, "bookings", orderId, {
    userId: order.userId,
    roomId: order.roomId,
    ownerId: room.ownerId || null,
    propertyName: room.propertyName || "Property",
    roomType: selectedRoom.type || "Room",
    occupancyIndex: order.occupancyIndex,
    moveInDate: order.moveInDate,
    roomPrice: order.roomPrice,
    bookingAmount: order.amount,
    status: "CONFIRMED",
    orderId,
    createdAt: new Date()
  });

  return true;
}

export const onRequestGet = async ({ env, params }) => {
  try {
    const orderId = params.orderId;
    const order = await getDocument(env, "orders", orderId);

    if (!order) {
      return jsonResponse(env, 404, { success: false, status: "NOT_FOUND" });
    }

    if (order.status === PAID_STATUS) {
      const bookingReady = await ensureBookingForOrder(env, orderId, order);

      return jsonResponse(env, 200, {
        success: bookingReady,
        status: bookingReady ? PAID_STATUS : "PAID_BOOKING_PENDING"
      });
    }

    const paidOnCashfree = await isCashfreeOrderPaid(env, orderId);

    if (!paidOnCashfree) {
      return jsonResponse(env, 200, { success: false, status: order.status || "PENDING" });
    }

    await updateDocument(env, "orders", orderId, {
      status: PAID_STATUS,
      paidAt: new Date()
    });

    const paidOrder = {
      ...order,
      status: PAID_STATUS,
      paidAt: new Date().toISOString()
    };

    const bookingReady = await ensureBookingForOrder(env, orderId, paidOrder);

    return jsonResponse(env, 200, {
      success: bookingReady,
      status: bookingReady ? PAID_STATUS : "PAID_BOOKING_PENDING"
    });
  } catch (error) {
    console.error(error);
    return jsonResponse(env, 500, { success: false, status: "ERROR" });
  }
};

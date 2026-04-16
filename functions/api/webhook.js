import { getDocument, setDocument, updateDocument } from "../_lib/firestore";
import { jsonResponse, optionsResponse } from "../_lib/http";

export const onRequestOptions = async ({ env }) => optionsResponse(env);

export const onRequestPost = async ({ request, env }) => {
  try {
    const payload = await request.json();

    if (payload?.type !== "PAYMENT_SUCCESS") {
      return jsonResponse(env, 200, { ok: true });
    }

    const orderId = payload?.data?.order?.order_id;

    if (!orderId) {
      return jsonResponse(env, 200, { ok: true });
    }

    const order = await getDocument(env, "orders", orderId);

    if (!order) {
      return jsonResponse(env, 200, { ok: true });
    }

    const existingBooking = await getDocument(env, "bookings", orderId);

    if (order.status === "PAID" || existingBooking) {
      return jsonResponse(env, 200, { ok: true });
    }

    const room = await getDocument(env, "rooms", order.roomId);

    if (!room) {
      return jsonResponse(env, 200, { ok: true });
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

    await updateDocument(env, "orders", orderId, {
      status: "PAID",
      paidAt: new Date()
    });

    return jsonResponse(env, 200, { ok: true });
  } catch (error) {
    console.error(error);
    return jsonResponse(env, 500, { ok: false });
  }
};

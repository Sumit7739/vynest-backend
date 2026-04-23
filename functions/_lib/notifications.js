import { getDocument, setDocument } from "./firestore";

function toDisplayAmount(value) {
  const amount = Number(value || 0);
  return Number.isFinite(amount) ? amount : 0;
}

export async function createPurchaseNotification(env, { orderId, order, room }) {
  if (!orderId || !order || !room) {
    return;
  }

  const notificationId = `purchase_${orderId}`;
  const existing = await getDocument(env, "notifications", notificationId);

  if (existing) {
    return;
  }

  const amount = toDisplayAmount(order.amount);
  const propertyName = room.propertyName || "Property";
  const roomType = room.roomDetails?.[Number(order.occupancyIndex)]?.type || "Room";

  await setDocument(env, "notifications", notificationId, {
    type: "PURCHASE_CREATED",
    title: "New Booking Purchase",
    message: `Booking payment received for ${propertyName} (${roomType})`,
    orderId,
    bookingId: orderId,
    roomId: order.roomId,
    propertyName,
    roomType,
    amount,
    currency: "INR",
    actorUserId: order.userId,
    ownerId: room.ownerId || null,
    targetIds: [order.userId, room.ownerId || ""].filter(Boolean),
    targetRoles: ["admin"],
    channels: ["in_app"],
    createdAt: new Date(),
    readBy: {}
  });
}

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
  const [studentProfile, ownerProfile] = await Promise.all([
    order.userId ? getDocument(env, "users", order.userId) : Promise.resolve(null),
    room.ownerId ? getDocument(env, "users", room.ownerId) : Promise.resolve(null),
  ]);

  const studentName =
    studentProfile?.fullName || studentProfile?.name || order.customerName || "Student";
  const ownerName = ownerProfile?.fullName || ownerProfile?.name || "Owner";
  const amountLabel = `INR ${amount}`;
  const message =
    `Amount: ${amountLabel}. Student: ${studentName}. ` +
    `Owner: ${ownerName}. Property: ${propertyName} (${roomType}).`;

  await setDocument(env, "notifications", notificationId, {
    type: "PURCHASE_CREATED",
    title: "New Booking Purchase",
    message,
    orderId,
    bookingId: orderId,
    roomId: order.roomId,
    propertyName,
    roomType,
    amount,
    amountLabel,
    studentName,
    ownerName,
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

export function calculateBookingFee(propertyType, roomType) {
  const normalizedPropertyType = (propertyType || "").toLowerCase();
  const normalizedRoomType = (roomType || "").toLowerCase();

  if (normalizedPropertyType === "hostel") {
    return 7000;
  }

  if (normalizedPropertyType === "pg_no_food") {
    return 1000;
  }

  if (normalizedPropertyType === "pg_with_food") {
    return 2000;
  }

  if (normalizedPropertyType === "flat") {
    if (normalizedRoomType.includes("1")) return 3000;
    if (normalizedRoomType.includes("2")) return 4000;
    if (normalizedRoomType.includes("3")) return 5000;
    if (normalizedRoomType.includes("4")) return 5000;
  }

  return null;
}

export function isValidDateInput(value) {
  if (typeof value !== "string") {
    return false;
  }

  return /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value));
}

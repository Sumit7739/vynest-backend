
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const { Cashfree } = require("cashfree-pg");

const app = express();
app.use(cors());
app.use(express.json());

const requiredEnv = (value, name) => {
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
};

// 🔐 FIREBASE ADMIN
const serviceAccount = JSON.parse(
  requiredEnv(process.env.FIREBASE_SERVICE_ACCOUNT_JSON, "FIREBASE_SERVICE_ACCOUNT_JSON"),
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const CLIENT_ID = requiredEnv(process.env.CASHFREE_CLIENT_ID, "CASHFREE_CLIENT_ID");
const CLIENT_SECRET = requiredEnv(
  process.env.CASHFREE_CLIENT_SECRET,
  "CASHFREE_CLIENT_SECRET",
);

Cashfree.XClientId = CLIENT_ID;
Cashfree.XClientSecret = CLIENT_SECRET;
Cashfree.XEnvironment = Cashfree.Environment.PRODUCTION;

const normalizeCustomerPhone = (value) => {
  const digits = String(value || "").replace(/\D/g, "");

  if (digits.length === 10) return digits;
  if (digits.length === 12 && digits.startsWith("91")) return digits.slice(2);

  return null;
};

const normalizeCustomerEmail = (value) => {
  const email = String(value || "").trim().toLowerCase();
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  return isValidEmail ? email : null;
};

const getBearerToken = (req) => {
  const authHeader = req.headers.authorization || "";
  const [scheme, token] = authHeader.split(" ");

  if (!scheme || scheme.toLowerCase() !== "bearer" || !token) {
    return null;
  }

  return token;
};

// ✅ CREATE ORDER
app.post("/create-order", async (req, res) => {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({ error: "Missing bearer token" });
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;

    const { amount, roomId, moveInDate, occupancyIndex } = req.body;

    if (!amount || !roomId) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const orderId = "order_" + Date.now();

    const userSnap = await db.collection("users").doc(userId).get();
    const userData = userSnap.exists ? userSnap.data() : {};
    const customerEmail = normalizeCustomerEmail(userData.email || decodedToken.email);
    const customerPhone = normalizeCustomerPhone(userData.phone);

    if (!customerEmail || !customerPhone) {
      return res.status(400).json({ error: "Missing valid customer phone or email in profile" });
    }

    const response = await Cashfree.PGCreateOrder({
      order_id: orderId,
      order_amount: amount,
      order_currency: "INR",
      customer_details: {
        customer_id: userId,
        customer_email: customerEmail,
        customer_phone: customerPhone,
      },
    });

    // 💾 SAVE PAYMENT (PENDING)
    await db.collection("payments").doc(orderId).set({
      userId,
      roomId,
      moveInDate,
      occupancyIndex,
      amount,
      status: "PENDING",
      createdAt: new Date(),
    });

    res.json({
      payment_session_id: response.data.payment_session_id,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Order creation failed" });
  }
});

// ✅ WEBHOOK (PAYMENT CONFIRMATION)
app.post("/webhook", async (req, res) => {
  try {
    const data = req.body;

    const orderId = data?.data?.order?.order_id;
    const status = data?.data?.payment?.payment_status;

    if (!orderId) return res.sendStatus(200);

    if (status === "SUCCESS") {
      const paymentRef = db.collection("payments").doc(orderId);
      const snap = await paymentRef.get();

      if (!snap.exists) return res.sendStatus(200);

      const payment = snap.data();

      // ✅ mark success
      await paymentRef.update({
        status: "SUCCESS",
        paidAt: new Date(),
      });

      // ✅ CREATE BOOKING
      await db.collection("bookings").add({
        userId: payment.userId,
        roomId: payment.roomId,
        moveInDate: payment.moveInDate,
        occupancyIndex: payment.occupancyIndex,
        amount: payment.amount,
        status: "CONFIRMED",
        createdAt: new Date(),
      });

      console.log("✅ Booking created:", orderId);
    }

    res.sendStatus(200);

  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

// 🌐 START SERVER
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on ${PORT}`));
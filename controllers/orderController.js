/**
 * ShadowSMM — Order Controller
 * Express 5 + MongoDB Native Driver + ES Modules
 *
 * Handles:
 * - Create order
 * - User order history
 * - Admin active order requests
 * - Approve order
 * - User cancellation request
 * - Admin cancellation
 * - Start Count / Delivered tracking
 * - Automatic Expected Total
 * - Completed / Partial status
 * - Order target accepts a full HTTP/HTTPS link or a plain @username
 *
 * Wallet: users.balance is stored in USD. Order charge is debited atomically
 * with the order and a permanent wallet transaction record. The same charge is
 * added to users.spent (shown as "Spent balance" on the dashboard).
 *
 * Provider and pricing are always resolved from the trusted server catalogue.
 *
 * Referral: a referral code typed in the order form (or a discount the user
 * already earned) is applied to the trusted charge on the server. The wallet is
 * debited with the discounted price. When an order is marked Completed, the
 * user's completed-order count is increased (this unlocks their own referral code).
 *
 * Referral reward: when an order that used a referral code is marked Completed,
 * it is counted for the referrer. Every 50 completed orders of a discount tier
 * pay the referrer a wallet reward (first tier = $0.30 one time, every later
 * tier = $0.10 only),
 * with a Referral Reward transaction and a notification.
 *
 * Refund: when an admin cancels an order, the full amount the user paid for it
 * (the discounted charge) is returned to the wallet in the same transaction.
 * A "refund" entry is saved in the transactions collection (shown in the user's
 * Funds History), the amount is removed from users.spent, and the user gets an
 * in-app notification.
 *
 * One-time referral use: once a user has placed an order with a referral code,
 * that same code cannot be used by that user again. The code is consumed inside
 * the same transaction that debits the wallet and creates the order.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ObjectId } from "mongodb";

import { connectDB, getUsersCollection } from "../config/db.js";

import {
    getOrdersCollection,
    parseObjectId,
    serializeOrder
} from "../models/Order.js";

import {
    applyReferralToOrder,
    incrementCompletedOrders,
    markReferralRedemptionUsed,
    recordReferralOrderCompleted
} from "../services/referralService.js";

import { sendTelegramMessage } from "../services/telegramService.js";

/* ============================================================
   CONSTANTS
============================================================ */

const MAX_QUANTITY = 100_000_000;
const MAX_CHARGE = 100_000_000;
const MAX_COUNT = 1_000_000_000_000;

const MAX_USER_ORDERS = 500;
const MAX_ADMIN_ORDERS = 1000;

const CONTROLLER_DIR = path.dirname(fileURLToPath(import.meta.url));

let serviceCatalogueCache = null;

const ALLOWED_PROTOCOLS = new Set([
    "http:",
    "https:"
]);

// @username: 1-64 chars after "@"; letters, numbers, ".", "_" and "-".
const USERNAME_PATTERN = /^@[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;

/* ============================================================
   RESPONSE HELPERS
============================================================ */

function sendError(res, status, message, extra = {}) {
    return res.status(status).json({
        success: false,
        message,
        ...(extra && typeof extra === "object" ? extra : {}),
        timestamp: new Date().toISOString()
    });
}

function handleError(res, action, error, message) {
    console.error(`[ORDERS] ${action}:`, error);

    return sendError(res, 500, message);
}

/* ============================================================
   INPUT VALIDATION
============================================================ */

function normalizeText(value, maxLength = 200) {
    if (typeof value !== "string") {
        return "";
    }

    return value
        .trim()
        .replace(/[\u0000-\u001F\u007F]/g, "")
        .slice(0, maxLength);
}

function parseNumber(value) {
    if (
        value === null ||
        value === undefined ||
        (
            typeof value === "string" &&
            value.trim() === ""
        )
    ) {
        return null;
    }

    const number = Number(value);

    return Number.isFinite(number) ? number : null;
}

function parseWholeNumber(
    value,
    min = 0,
    max = MAX_COUNT
) {
    const number = parseNumber(value);

    if (
        number === null ||
        !Number.isSafeInteger(number) ||
        number < min ||
        number > max
    ) {
        return null;
    }

    return number;
}

function parseCharge(value) {
    const amount = parseNumber(value);

    if (
        amount === null ||
        amount < 0 ||
        amount > MAX_CHARGE
    ) {
        return null;
    }

    return Math.round(
        (amount + Number.EPSILON) * 100
    ) / 100;
}

function isValidWebUrl(value) {
    if (typeof value !== "string" || /\s/.test(value)) {
        return false;
    }

    try {
        const parsed = new URL(value);

        return (
            ALLOWED_PROTOCOLS.has(parsed.protocol) &&
            Boolean(parsed.hostname) &&
            // Real public domain only (rejects localhost / bare hosts).
            parsed.hostname.includes(".") &&
            // Reject links carrying embedded credentials.
            !parsed.username &&
            !parsed.password
        );
    } catch {
        return false;
    }
}

function isValidUsername(value) {
    return (
        typeof value === "string" &&
        USERNAME_PATTERN.test(value)
    );
}

/*
 * Order target can be either:
 * - a full HTTP/HTTPS link  -> https://instagram.com/username
 * - a plain @username       -> @username
 *
 * Returns the cleaned target string, or null when invalid.
 */
function parseOrderTarget(value) {
    if (typeof value !== "string") {
        return null;
    }

    const target = value.trim();

    if (!target) {
        return null;
    }

    if (target.startsWith("@")) {
        return isValidUsername(target) ? target : null;
    }

    return isValidWebUrl(target) ? target : null;
}

/* ============================================================
   AUTHENTICATED USER HELPERS
============================================================ */

function getAuthenticatedObjectId(req) {
    const payload = req.user;

    if (!payload || typeof payload !== "object") {
        return null;
    }

    const candidates = [
        payload.userId,
        payload.id,
        payload._id,
        payload.sub
    ];

    for (const candidate of candidates) {
        if (
            typeof candidate !== "string" ||
            !ObjectId.isValid(candidate)
        ) {
            continue;
        }

        const id = new ObjectId(candidate);

        if (id.toHexString() === candidate.toLowerCase()) {
            return id;
        }
    }

    return null;
}

function isAdmin(req) {
    return req.user?.role === "admin";
}

function getAdminActor(req) {
    const id = getAuthenticatedObjectId(req);

    return id ? id.toHexString() : "admin";
}

function createOrderNumber() {
    return (
        "SSM-" +
        Date.now().toString(36).toUpperCase() +
        "-" +
        crypto.randomBytes(4).toString("hex").toUpperCase()
    );
}

/* ============================================================
   SERIALIZATION
============================================================ */

function publicOrder(order) {
    // Never expose internal provider routing to customers.
    const serialized = serializeOrder(order);

    if (!serialized || typeof serialized !== "object") {
        return serialized;
    }

    const safe = { ...serialized };

    delete safe.provider;
    delete safe.providerServiceId;
    delete safe.provider_service_id;

    return safe;
}

function adminOrder(order) {
    // Only admin endpoints return internal provider details.
    return serializeOrder(order);
}

/* ============================================================
   TRUSTED SERVER-SIDE SERVICE CATALOGUE

   Recommended location:
   backend/data/services-data.json

   Alternatively set:
   SMM_SERVICES_CATALOGUE_PATH=/absolute/path/services-data.json

   Expected row:
   [id, name, rate, min, max, description, provider, providerServiceId]
============================================================ */

function findCataloguePath() {
    const configured = normalizeText(
        process.env.SMM_SERVICES_CATALOGUE_PATH,
        2000
    );

    const candidates = [
        configured,
        path.resolve(CONTROLLER_DIR, "../data/services-data.json"),
        path.resolve(CONTROLLER_DIR, "../../data/services-data.json"),
        path.resolve(CONTROLLER_DIR, "../services-data.json"),
        path.resolve(CONTROLLER_DIR, "../../services-data.json"),
        path.resolve(CONTROLLER_DIR, "../public/services-data.json"),
        path.resolve(CONTROLLER_DIR, "../../public/services-data.json"),
        path.resolve(process.cwd(), "services-data.json"),
        path.resolve(process.cwd(), "data/services-data.json"),
        path.resolve(process.cwd(), "public/services-data.json")
    ].filter(Boolean);

    return candidates.find((candidate) => {
        try {
            return (
                fs.existsSync(candidate) &&
                fs.statSync(candidate).isFile()
            );
        } catch {
            return false;
        }
    }) || null;
}

function getServiceCatalogue() {
    if (serviceCatalogueCache) {
        return serviceCatalogueCache;
    }

    const cataloguePath = findCataloguePath();

    if (!cataloguePath) {
        const error = new Error(
            "Trusted services-data.json was not found. Place it at backend/data/services-data.json or set SMM_SERVICES_CATALOGUE_PATH."
        );

        error.code = "SERVICE_CATALOGUE_NOT_FOUND";
        throw error;
    }

    let data;

    try {
        data = JSON.parse(
            fs.readFileSync(cataloguePath, "utf8")
        );
    } catch (cause) {
        const error = new Error(
            "Trusted services-data.json is invalid JSON.",
            { cause }
        );

        error.code = "SERVICE_CATALOGUE_INVALID";
        throw error;
    }

    const map = new Map();

    const addService = (platform, categoryName, row) => {
        if (!Array.isArray(row) || row.length < 8) {
            return;
        }

        const [
            id,
            name,
            rate,
            min,
            max,
            description,
            provider,
            providerServiceId
        ] = row;

        const serviceId = String(id ?? "").trim();

        if (!serviceId) {
            return;
        }

        const parsedRate = Number(rate);
        const parsedMin = Number(min);
        const parsedMax = Number(max);

        map.set(serviceId, {
            serviceId,
            serviceName: normalizeText(name, 240),

            rate:
                Number.isFinite(parsedRate) && parsedRate >= 0
                    ? parsedRate
                    : null,

            min:
                Number.isSafeInteger(parsedMin) && parsedMin >= 1
                    ? parsedMin
                    : null,

            max:
                Number.isSafeInteger(parsedMax) && parsedMax >= 1
                    ? parsedMax
                    : null,

            description: normalizeText(description, 2000),

            provider: normalizeText(provider, 120).toLowerCase(),

            providerServiceId:
                providerServiceId === null ||
                    providerServiceId === undefined
                    ? null
                    : String(providerServiceId).trim(),

            platform: normalizeText(platform, 120),

            catalogueCategory: normalizeText(categoryName, 240)
        });
    };

    if (
        !data ||
        typeof data !== "object" ||
        Array.isArray(data)
    ) {
        const error = new Error(
            "Trusted services-data.json must contain a platform object."
        );

        error.code = "SERVICE_CATALOGUE_INVALID";
        throw error;
    }

    /*
     * Supported catalogue format:
     *
     * {
     *   "youtube": [
     *     [
     *       "Subscribers",
     *       [
     *         [
     *           1,
     *           "Service name",
     *           10,
     *           100,
     *           100000,
     *           "",
     *           "fastboostingpoint",
     *           2510
     *         ]
     *       ]
     *     ]
     *   ]
     * }
     */

    for (const [platform, categories] of Object.entries(data)) {
        if (!Array.isArray(categories)) {
            continue;
        }

        for (const category of categories) {
            if (
                !Array.isArray(category) ||
                category.length < 2 ||
                !Array.isArray(category[1])
            ) {
                continue;
            }

            const [categoryName, serviceRows] = category;

            for (const row of serviceRows) {
                addService(platform, categoryName, row);
            }
        }
    }

    if (map.size === 0) {
        const error = new Error(
            "No valid services were found in trusted services-data.json."
        );

        error.code = "SERVICE_CATALOGUE_INVALID";
        throw error;
    }

    serviceCatalogueCache = map;

    console.info(
        `[ORDERS] Loaded ${map.size} services from trusted catalogue: ${cataloguePath}`
    );

    return serviceCatalogueCache;
}

function calculateTrustedCharge(rate, quantity) {
    const amount = (rate * quantity) / 1000;

    if (
        !Number.isFinite(amount) ||
        amount < 0 ||
        amount > MAX_CHARGE
    ) {
        return null;
    }

    return Math.round(
        (amount + Number.EPSILON) * 100
    ) / 100;
}

function getUpdatedDocument(result) {
    // Supports MongoDB driver results with or without .value.
    return result?.value ?? result ?? null;
}

/*
 * Same as above, but a "not found" result ({ value: null, ok: 1 } on older
 * drivers) is returned as null. Used where a missed match must be detected.
 */
function getFoundDocument(result) {
    if (
        result &&
        typeof result === "object" &&
        "value" in result &&
        "ok" in result
    ) {
        return result.value ?? null;
    }

    return result ?? null;
}

/* ============================================================
   CREATE ORDER
   POST /api/orders
============================================================ */

export async function createOrder(req, res) {
    try {
        const userId = getAuthenticatedObjectId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "Your login session is invalid. Please log in again."
            );
        }

        const body =
            req.body &&
                typeof req.body === "object" &&
                !Array.isArray(req.body)
                ? req.body
                : {};

        const category = normalizeText(body.category, 120);
        const serviceId = normalizeText(body.serviceId, 120);
        const link = normalizeText(body.link, 2000);

        // Optional referral code typed in the order form.
        const referralCodeInput = normalizeText(body.referralCode, 100);

        const quantity = parseWholeNumber(
            body.quantity,
            1,
            MAX_QUANTITY
        );

        if (!serviceId) {
            return sendError(
                res,
                400,
                "Please select a valid service."
            );
        }

        let trustedService;

        try {
            trustedService = getServiceCatalogue().get(serviceId);
        } catch (catalogueError) {
            console.error(
                "[ORDERS] Service catalogue error:",
                catalogueError
            );

            return sendError(
                res,
                503,
                catalogueError?.code === "SERVICE_CATALOGUE_NOT_FOUND"
                    ? "Order services are temporarily unavailable. Please contact support."
                    : "The service catalogue could not be loaded. Please contact support."
            );
        }

        if (!trustedService) {
            return sendError(
                res,
                400,
                "Selected service was not found. Please refresh services and try again."
            );
        }

        // Provider is derived only from the trusted server-side catalogue.
        if (
            !trustedService.provider ||
            !trustedService.providerServiceId
        ) {
            return sendError(
                res,
                400,
                "This service is temporarily unavailable. Please choose another service."
            );
        }

        if (
            trustedService.rate === null ||
            trustedService.min === null ||
            trustedService.max === null
        ) {
            return sendError(
                res,
                503,
                "Pricing for this service is unavailable. Please contact support."
            );
        }

        if (quantity === null) {
            return sendError(
                res,
                400,
                `Quantity must be a whole number between 1 and ${MAX_QUANTITY}.`
            );
        }

        if (
            quantity < trustedService.min ||
            quantity > trustedService.max
        ) {
            return sendError(
                res,
                400,
                `Quantity for this service must be between ${trustedService.min} and ${trustedService.max}.`
            );
        }

        // Never trust req.body.charge.
        const baseCharge = calculateTrustedCharge(
            trustedService.rate,
            quantity
        );

        if (baseCharge === null) {
            return sendError(
                res,
                400,
                "Unable to calculate a valid charge for this order."
            );
        }

        const orderTarget = parseOrderTarget(link);

        if (!orderTarget) {
            return sendError(
                res,
                400,
                "Enter a valid HTTP/HTTPS order link or an @username."
            );
        }

        const db = await connectDB();
        const users = await getUsersCollection();
        const orders = await getOrdersCollection();
        const transactions = db.collection("transactions");

        // Read the user's current USD wallet balance.
        const user = await users.findOne(
            { _id: userId },
            {
                projection: {
                    username: 1,
                    balance: 1,
                    isActive: 1,
                    status: 1
                }
            }
        );

        if (!user) {
            return sendError(
                res,
                401,
                "User account was not found. Please log in again."
            );
        }

        if (
            user.isActive === false ||
            String(user.status || "").toLowerCase() === "blocked"
        ) {
            return sendError(
                res,
                403,
                "Your account is not allowed to place orders."
            );
        }

        /*
         * Referral discount (server-side only).
         *
         * - A code typed in the form is checked and saved on the account
         *   the first time it is used.
         * - A discount the user already earned is applied automatically.
         * The wallet is then charged the discounted price.
         */
        let pricing;

        try {
            pricing = await applyReferralToOrder(
                userId,
                referralCodeInput,
                baseCharge
            );
        } catch (referralError) {
            const status = Number(referralError?.statusCode);

            if (
                Number.isInteger(status) &&
                status >= 400 &&
                status < 500
            ) {
                return sendError(
                    res,
                    status,
                    referralError.message,
                    { code: "REFERRAL_ERROR" }
                );
            }

            throw referralError;
        }

        const charge = pricing.finalAmount;

        const initialBalance = Number(user.balance ?? 0);

        if (
            !Number.isFinite(initialBalance) ||
            initialBalance < 0
        ) {
            return sendError(
                res,
                500,
                "Your wallet balance is invalid. Please contact support."
            );
        }

        if (initialBalance + Number.EPSILON < charge) {
            return sendError(
                res,
                400,
                "Insufficient funds. Please add funds and try again.",
                {
                    code: "INSUFFICIENT_FUNDS",
                    balance: initialBalance,
                    required: charge
                }
            );
        }

        const now = new Date();

        let balanceBefore = initialBalance;

        let balanceAfter = Math.round(
            (initialBalance - charge + Number.EPSILON) * 100
        ) / 100;

        const order = {
            orderNumber: createOrderNumber(),

            userId,

            username:
                normalizeText(user.username, 120) ||
                normalizeText(req.user?.username, 120) ||
                "Unknown user",

            category:
                trustedService.catalogueCategory ||
                category ||
                trustedService.platform,

            serviceName: trustedService.serviceName,
            serviceId: trustedService.serviceId,

            // Internal fields: only admin endpoints expose them.
            provider: trustedService.provider,
            providerServiceId: trustedService.providerServiceId,
            serviceRate: trustedService.rate,

            link: orderTarget,

            quantity,
            charge,
            currency: "USD",

            // Price before the referral discount, and the discount applied.
            originalCharge: pricing.originalAmount,
            referralCode: pricing.referralCode,
            referralDiscountPercent: pricing.discountPercent,
            referralDiscountAmount: pricing.discountAmount,

            // Used to count this order for the referrer's reward when it completes.
            referralRedemptionId: pricing.redemptionId ?? null,
            referralReferrerId: pricing.referrerId ?? null,
            referralTier: pricing.tier ?? null,

            startCount: null,
            delivered: null,
            expectedTotal: null,

            status: "processing",

            cancellationRequested: false,
            cancellationRequestedAt: null,
            cancellationHandledAt: null,

            active: true,

            createdAt: now,
            updatedAt: now,

            approvedAt: null,
            completedAt: null,
            cancelledAt: null,

            history: [
                {
                    action: "created",
                    by: userId.toHexString(),
                    at: now
                }
            ]
        };

        /*
         * Wallet debit + order insert + transaction ledger entry
         * are performed in one MongoDB transaction.
         *
         * MongoDB transactions require a replica set or a supported
         * sharded cluster. A standalone MongoDB server is insufficient.
         */

        const session = db.client?.startSession?.();

        if (!session) {
            return sendError(
                res,
                500,
                "Wallet transactions are unavailable on this database connection. Please contact support."
            );
        }

        try {
            await session.withTransaction(async () => {
                // Re-read the wallet inside the transaction.
                const walletUser = await users.findOne(
                    { _id: userId },
                    {
                        session,
                        projection: {
                            balance: 1
                        }
                    }
                );

                if (!walletUser) {
                    throw new Error("ORDER_USER_NOT_FOUND");
                }

                balanceBefore = Number(walletUser.balance ?? 0);

                if (
                    !Number.isFinite(balanceBefore) ||
                    balanceBefore < 0
                ) {
                    throw new Error("ORDER_INVALID_BALANCE");
                }

                if (balanceBefore + Number.EPSILON < charge) {
                    throw new Error("ORDER_INSUFFICIENT_FUNDS");
                }

                balanceAfter = Math.round(
                    (balanceBefore - charge + Number.EPSILON) * 100
                ) / 100;

                // Conditional debit prevents spending the same balance twice.
                // The same amount is added to the user's lifetime `spent` total.
                const debit = await users.updateOne(
                    {
                        _id: userId,
                        balance: { $gte: charge }
                    },
                    {
                        $inc: {
                            balance: -charge,
                            spent: charge
                        }
                    },
                    { session }
                );

                if (debit.modifiedCount !== 1) {
                    throw new Error("ORDER_INSUFFICIENT_FUNDS");
                }

                const inserted = await orders.insertOne(
                    order,
                    { session }
                );

                order._id = inserted.insertedId;

                /*
                 * Consume the referral code with this order. If it was already
                 * used (for example by an order sent at the same moment), the
                 * whole transaction is rolled back: no debit, no order.
                 */
                if (pricing.redemptionId) {
                    const consumed = await markReferralRedemptionUsed(
                        pricing.redemptionId,
                        userId,
                        order,
                        session
                    );

                    if (!consumed) {
                        throw new Error("ORDER_REFERRAL_ALREADY_USED");
                    }
                }

                // Permanent wallet transaction ledger entry.
                await transactions.insertOne(
                    {
                        transactionId: `ORD-${order.orderNumber}`,

                        // Unique per order: the transactions collection has a
                        // unique index on requestId, so it must never be null.
                        requestId: `ORD-${order.orderNumber}`,

                        userId,
                        username: order.username,

                        type: "payment",
                        method: "wallet",

                        amount: charge,
                        currency: "USD",

                        originalAmount: pricing.originalAmount,
                        referralDiscountPercent:
                            pricing.discountPercent,

                        balanceBefore,
                        balanceAfter,

                        status: "completed",

                        orderId: inserted.insertedId,
                        orderNumber: order.orderNumber,

                        description:
                            `Payment for order ${order.orderNumber}`,

                        createdAt: now
                    },
                    { session }
                );
            });
        } catch (transactionError) {
            if (
                transactionError?.message === "ORDER_USER_NOT_FOUND"
            ) {
                return sendError(
                    res,
                    401,
                    "User account was not found. Please log in again."
                );
            }

            if (
                transactionError?.message === "ORDER_INVALID_BALANCE"
            ) {
                return sendError(
                    res,
                    500,
                    "Your wallet balance is invalid. Please contact support."
                );
            }

            if (
                transactionError?.message === "ORDER_INSUFFICIENT_FUNDS"
            ) {
                return sendError(
                    res,
                    400,
                    "Insufficient funds. Please add funds and try again.",
                    {
                        code: "INSUFFICIENT_FUNDS"
                    }
                );
            }

            if (
                transactionError?.message === "ORDER_REFERRAL_ALREADY_USED"
            ) {
                return sendError(
                    res,
                    409,
                    "You have already used this referral code on an order. A referral code can only be used once.",
                    { code: "REFERRAL_ERROR" }
                );
            }

            throw transactionError;
        } finally {
            await session.endSession();
        }

        /*
         * Telegram admin notification.
         * Sent only after the transaction has committed and the session is
         * closed, so a retried transaction callback can never notify twice.
         * It is not awaited and every failure is only logged, so Telegram can
         * never delay or break a successfully placed order.
         */
        try {
            const telegramMessage = [
                "📦 NEW SHADOWSMM ORDER",
                "",
                `Order ID: ${order.orderNumber}`,
                `User: ${order.username}`,
                `Service: ${order.serviceName}`,
                `Category: ${order.category}`,
                `Quantity: ${order.quantity}`,
                `Charge: $${Number(order.charge).toFixed(2)} USD`,
                `Status: ${order.status}`,
                `Time: ${new Date().toISOString()}`
            ].join("\n");

            sendTelegramMessage(telegramMessage).catch(
                (telegramError) => {
                    console.error(
                        `[ORDERS] createOrder: Telegram notification failed for order ${order.orderNumber}:`,
                        telegramError?.message || telegramError
                    );
                }
            );
        } catch (telegramError) {
            console.error(
                `[ORDERS] createOrder: could not send Telegram notification for order ${order.orderNumber}:`,
                telegramError?.message || telegramError
            );
        }

        return res.status(201).json({
            success: true,
            message: "Order placed successfully.",

            balance: balanceAfter,

            orderId: String(order._id),
            id: String(order._id),

            referral: {
                code: pricing.referralCode,
                redeemedNow: pricing.redeemedNow,
                discountPercent: pricing.discountPercent,
                discountAmount: pricing.discountAmount,
                originalCharge: pricing.originalAmount,
                finalCharge: charge
            },

            order: publicOrder(order)
        });
    } catch (error) {
        return handleError(
            res,
            "createOrder",
            error,
            "Unable to place your order right now."
        );
    }
}

/* ============================================================
   GET USER ORDERS
   GET /api/orders
============================================================ */

export async function getUserOrders(req, res) {
    try {
        const userId = getAuthenticatedObjectId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "Your login session is invalid."
            );
        }

        const orders = await getOrdersCollection();

        const rows = await orders
            .find({ userId })
            .sort({ createdAt: -1 })
            .limit(MAX_USER_ORDERS)
            .toArray();

        return res.json({
            success: true,
            orders: rows.map(publicOrder)
        });
    } catch (error) {
        return handleError(
            res,
            "getUserOrders",
            error,
            "Unable to load your orders."
        );
    }
}

/* ============================================================
   GET ADMIN ORDERS
   GET /api/orders/admin

   Returns active requests only.
   Historical records are not deleted.
============================================================ */

export async function getAdminOrders(req, res) {
    try {
        if (!isAdmin(req)) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const orders = await getOrdersCollection();

        const rows = await orders
            .find({ active: true })
            .sort({ createdAt: 1 })
            .limit(MAX_ADMIN_ORDERS)
            .toArray();

        return res.json({
            success: true,
            orders: rows.map(adminOrder)
        });
    } catch (error) {
        return handleError(
            res,
            "getAdminOrders",
            error,
            "Unable to load order requests."
        );
    }
}

/* ============================================================
   APPROVE ORDER
   PATCH /api/orders/admin/:id/approve

   Processing -> In Progress
============================================================ */

export async function approveOrder(req, res) {
    try {
        if (!isAdmin(req)) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const id = parseObjectId(req.params.id);

        if (!id) {
            return sendError(
                res,
                400,
                "Invalid order ID."
            );
        }

        const now = new Date();

        const orders = await getOrdersCollection();

        const result = await orders.findOneAndUpdate(
            {
                _id: id,
                active: true,
                status: "processing"
            },
            {
                $set: {
                    status: "in_progress",
                    approvedAt: now,
                    updatedAt: now,
                    cancellationHandledAt: now
                },
                $push: {
                    history: {
                        action: "approved",
                        by: getAdminActor(req),
                        at: now
                    }
                }
            },
            { returnDocument: "after" }
        );

        const order = getUpdatedDocument(result);

        if (!order) {
            return sendError(
                res,
                409,
                "This order is no longer Processing or has already been handled. Refresh the list."
            );
        }

        return res.json({
            success: true,
            message: "Order approved and moved to In Progress.",
            order: adminOrder(order)
        });
    } catch (error) {
        return handleError(
            res,
            "approveOrder",
            error,
            "Unable to approve this order."
        );
    }
}

/* ============================================================
   USER REQUESTS CANCELLATION
   POST /api/orders/:id/cancel-request

   Status remains Processing until admin cancels.
============================================================ */

export async function requestCancellation(req, res) {
    try {
        const userId = getAuthenticatedObjectId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "Your login session is invalid."
            );
        }

        const id = parseObjectId(req.params.id);

        if (!id) {
            return sendError(
                res,
                400,
                "Invalid order ID."
            );
        }

        const now = new Date();

        const orders = await getOrdersCollection();

        const result = await orders.findOneAndUpdate(
            {
                _id: id,
                userId,
                active: true,
                status: "processing",
                cancellationRequested: { $ne: true }
            },
            {
                $set: {
                    cancellationRequested: true,
                    cancellationRequestedAt: now,
                    updatedAt: now
                },
                $push: {
                    history: {
                        action: "cancellation_requested",
                        by: userId.toHexString(),
                        at: now
                    }
                }
            },
            { returnDocument: "after" }
        );

        const order = getUpdatedDocument(result);

        if (!order) {
            return sendError(
                res,
                409,
                "Cancellation is unavailable, or a request has already been sent."
            );
        }

        return res.json({
            success: true,
            message: "Cancellation request sent. Order remains Processing until admin acts.",
            order: publicOrder(order)
        });
    } catch (error) {
        return handleError(
            res,
            "requestCancellation",
            error,
            "Unable to send cancellation request."
        );
    }
}

/* ============================================================
   ADMIN CANCELS ORDER
   PATCH /api/orders/admin/:id/cancel

   Processing -> Cancelled
   active=false removes it from active admin requests.
   Database record and user history remain.

   Refund: the full amount the user paid for this order is returned
   to the wallet, in the same MongoDB transaction as the cancellation.
   - A "refund" entry is added to the transactions collection
     (shows in the user's Funds History).
   - The amount is also removed from users.spent.
   - Only one cancel can ever succeed, so a refund is never paid twice.
============================================================ */

export async function cancelOrderByAdmin(req, res) {
    try {
        if (!isAdmin(req)) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const id = parseObjectId(req.params.id);

        if (!id) {
            return sendError(
                res,
                400,
                "Invalid order ID."
            );
        }

        const db = await connectDB();
        const users = await getUsersCollection();
        const orders = await getOrdersCollection();
        const transactions = db.collection("transactions");
        const notifications = db.collection("notifications");

        const adminActor = getAdminActor(req);

        const session = db.client?.startSession?.();

        if (!session) {
            return sendError(
                res,
                500,
                "Wallet transactions are unavailable on this database connection. Please contact support."
            );
        }

        let order = null;
        let refund = null;

        try {
            await session.withTransaction(async () => {
                // withTransaction may run this function again after a transient error.
                order = null;
                refund = null;

                const now = new Date();

                // Only an active Processing order can be cancelled.
                const existing = await orders.findOne(
                    {
                        _id: id,
                        active: true,
                        status: "processing"
                    },
                    { session }
                );

                if (!existing) {
                    throw new Error("ORDER_NOT_CANCELLABLE");
                }

                // The user gets back exactly what they paid (after any referral discount).
                const refundAmount = parseCharge(existing.charge) ?? 0;

                const transactionId =
                    `REF-${existing.orderNumber}`;

                const history = [
                    {
                        action: "cancelled_by_admin",
                        by: adminActor,
                        at: now
                    }
                ];

                if (refundAmount > 0) {
                    history.push({
                        action: "refunded",
                        amount: refundAmount,
                        by: adminActor,
                        at: now
                    });
                }

                // The status filter makes sure only one cancel can succeed.
                const cancelled = getFoundDocument(
                    await orders.findOneAndUpdate(
                        {
                            _id: id,
                            active: true,
                            status: "processing"
                        },
                        {
                            $set: {
                                status: "cancelled",
                                active: false,
                                cancelledAt: now,
                                updatedAt: now,
                                cancellationHandledAt: now,
                                cancellationRequested: false,

                                refundedAmount: refundAmount,
                                refundedAt:
                                    refundAmount > 0 ? now : null,
                                refundTransactionId:
                                    refundAmount > 0
                                        ? transactionId
                                        : null
                            },
                            $push: {
                                history: { $each: history }
                            }
                        },
                        {
                            returnDocument: "after",
                            session
                        }
                    )
                );

                if (!cancelled) {
                    throw new Error("ORDER_NOT_CANCELLABLE");
                }

                order = cancelled;

                if (refundAmount <= 0) {
                    return;
                }

                // Give the money back and lower the user's spent total.
                const before = getFoundDocument(
                    await users.findOneAndUpdate(
                        { _id: cancelled.userId },
                        {
                            $inc: {
                                balance: refundAmount,
                                spent: -refundAmount
                            },
                            $set: {
                                updatedAt: now
                            }
                        },
                        {
                            returnDocument: "before",
                            projection: { balance: 1 },
                            session
                        }
                    )
                );

                if (!before) {
                    throw new Error("ORDER_REFUND_USER_NOT_FOUND");
                }

                const balanceBefore = Number(before.balance ?? 0);

                if (!Number.isFinite(balanceBefore)) {
                    throw new Error("ORDER_REFUND_INVALID_BALANCE");
                }

                const balanceAfter = Math.round(
                    (balanceBefore + refundAmount + Number.EPSILON) * 100
                ) / 100;

                // spent never goes below 0 (older orders were placed before spent was tracked).
                await users.updateOne(
                    {
                        _id: cancelled.userId,
                        spent: { $lt: 0 }
                    },
                    {
                        $set: { spent: 0 }
                    },
                    { session }
                );

                // Permanent wallet ledger entry, shown in Funds History as a Refund.
                await transactions.insertOne(
                    {
                        transactionId,

                        // Unique per order (the transactions collection has a
                        // unique index on requestId, so it must never be null).
                        requestId: transactionId,

                        userId: cancelled.userId,
                        username: cancelled.username,

                        type: "refund",
                        method: "wallet",

                        amount: refundAmount,
                        currency: "USD",

                        balanceBefore,
                        balanceAfter,

                        status: "completed",

                        orderId: cancelled._id,
                        orderNumber: cancelled.orderNumber,

                        description:
                            `Refund for cancelled order ${cancelled.orderNumber}`,

                        createdAt: now
                    },
                    { session }
                );

                // User notification (same format as the deposit notifications).
                await notifications.insertOne(
                    {
                        userId: cancelled.userId,
                        title: "Order refunded",
                        message:
                            `Your order ${cancelled.orderNumber} was cancelled. $${refundAmount.toFixed(2)} has been refunded to your balance.`,
                        type: "order_refund",
                        metadata: {
                            orderId: String(cancelled._id),
                            orderNumber: cancelled.orderNumber,
                            refundedAmount: refundAmount,
                            currency: "USD",
                            transactionId
                        },
                        read: false,
                        createdAt: now
                    },
                    { session }
                );

                refund = {
                    amount: refundAmount,
                    transactionId,
                    balanceBefore,
                    balanceAfter
                };
            });
        } catch (transactionError) {
            if (
                transactionError?.message === "ORDER_NOT_CANCELLABLE"
            ) {
                return sendError(
                    res,
                    409,
                    "Only an active Processing order can be cancelled. It may already have been approved or handled."
                );
            }

            if (
                transactionError?.message === "ORDER_REFUND_USER_NOT_FOUND"
            ) {
                return sendError(
                    res,
                    500,
                    "The user's wallet was not found, so the refund could not be made. The order was not cancelled."
                );
            }

            if (
                transactionError?.message === "ORDER_REFUND_INVALID_BALANCE"
            ) {
                return sendError(
                    res,
                    500,
                    "The user's wallet balance is invalid, so the refund could not be made. The order was not cancelled."
                );
            }

            throw transactionError;
        } finally {
            await session.endSession();
        }

        return res.json({
            success: true,
            message: refund
                ? `Order cancelled and $${refund.amount.toFixed(2)} refunded to the user's wallet. Active request removed; user history preserved.`
                : "Order cancelled. Active request removed; user history preserved.",
            refund,
            order: adminOrder(order)
        });
    } catch (error) {
        return handleError(
            res,
            "cancelOrderByAdmin",
            error,
            "Unable to cancel this order."
        );
    }
}

/* ============================================================
   UPDATE TRACKING
   PATCH /api/orders/admin/:id/tracking

   Accepts startCount, delivered, or both.
   Blank values reset a field to null.
   Expected Total = Start Count + Delivered.
============================================================ */

export async function updateOrderTracking(req, res) {
    try {
        if (!isAdmin(req)) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const id = parseObjectId(req.params.id);

        if (!id) {
            return sendError(
                res,
                400,
                "Invalid order ID."
            );
        }

        const body =
            req.body &&
                typeof req.body === "object" &&
                !Array.isArray(req.body)
                ? req.body
                : {};

        const set = {
            updatedAt: new Date()
        };

        const changed = [];

        for (const field of ["startCount", "delivered"]) {
            if (!Object.prototype.hasOwnProperty.call(body, field)) {
                continue;
            }

            const value = body[field];

            if (
                value === null ||
                (typeof value === "string" && value.trim() === "")
            ) {
                set[field] = null;
            } else {
                const number = parseWholeNumber(
                    value,
                    0,
                    MAX_COUNT
                );

                if (number === null) {
                    return sendError(
                        res,
                        400,
                        `${field} must be a non-negative whole number or blank.`
                    );
                }

                set[field] = number;
            }

            changed.push(field);
        }

        if (changed.length === 0) {
            return sendError(
                res,
                400,
                "Provide startCount and/or delivered."
            );
        }

        const now = new Date();
        const orders = await getOrdersCollection();

        /*
         * Calculate Expected Total using the existing stored values
         * and whichever tracking values are being updated.
         */
        const existing = await orders.findOne({
            _id: id,
            active: true,
            status: "in_progress"
        });

        if (!existing) {
            return sendError(
                res,
                409,
                "Tracking can only be updated for an active In Progress order."
            );
        }

        const nextStartCount =
            Object.prototype.hasOwnProperty.call(set, "startCount")
                ? set.startCount
                : existing.startCount;

        const nextDelivered =
            Object.prototype.hasOwnProperty.call(set, "delivered")
                ? set.delivered
                : existing.delivered;

        set.expectedTotal =
            Number.isSafeInteger(nextStartCount) &&
                nextStartCount >= 0 &&
                Number.isSafeInteger(nextDelivered) &&
                nextDelivered >= 0
                ? nextStartCount + nextDelivered
                : null;

        const result = await orders.findOneAndUpdate(
            {
                _id: id,
                active: true,
                status: "in_progress"
            },
            {
                $set: set,
                $push: {
                    history: {
                        action: "tracking_updated",
                        fields: changed,
                        by: getAdminActor(req),
                        at: now
                    }
                }
            },
            { returnDocument: "after" }
        );

        const order = getUpdatedDocument(result);

        if (!order) {
            return sendError(
                res,
                409,
                "Tracking could not be updated. Refresh and try again."
            );
        }

        return res.json({
            success: true,
            message: "Tracking updated.",
            order: adminOrder(order)
        });
    } catch (error) {
        return handleError(
            res,
            "updateOrderTracking",
            error,
            "Unable to update tracking details."
        );
    }
}

/* ============================================================
   COMPLETE ORDER
   PATCH /api/orders/admin/:id/complete

   Both tracking fields must be set.
   Delivered >= quantity -> completed
   Delivered < quantity  -> partial

   Removes from active admin list; keeps database history.
============================================================ */

export async function completeOrder(req, res) {
    try {
        if (!isAdmin(req)) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const id = parseObjectId(req.params.id);

        if (!id) {
            return sendError(
                res,
                400,
                "Invalid order ID."
            );
        }

        const orders = await getOrdersCollection();

        const existing = await orders.findOne({
            _id: id,
            active: true,
            status: "in_progress"
        });

        if (!existing) {
            return sendError(
                res,
                409,
                "Only an active In Progress order can be completed."
            );
        }

        if (
            !Number.isSafeInteger(existing.startCount) ||
            existing.startCount < 0 ||
            !Number.isSafeInteger(existing.delivered) ||
            existing.delivered < 0
        ) {
            return sendError(
                res,
                400,
                "Set both Start Count and Delivered before completing this order."
            );
        }

        const status =
            existing.delivered >= existing.quantity
                ? "completed"
                : "partial";

        const now = new Date();

        const result = await orders.findOneAndUpdate(
            {
                _id: id,
                active: true,
                status: "in_progress",
                startCount: existing.startCount,
                delivered: existing.delivered
            },
            {
                $set: {
                    status,
                    active: false,
                    expectedTotal:
                        existing.startCount + existing.delivered,
                    completedAt: now,
                    updatedAt: now
                },
                $push: {
                    history: {
                        action: status,
                        by: getAdminActor(req),
                        at: now
                    }
                }
            },
            { returnDocument: "after" }
        );

        const order = getUpdatedDocument(result);

        if (!order) {
            return sendError(
                res,
                409,
                "Order details changed while completing. Refresh and try again."
            );
        }

        /*
         * Referral: a fully delivered order counts towards the user's
         * completed orders (50 unlocks their referral code).
         * The status filter above lets an order reach this point only once.
         * A failure here must not undo the completion, so it is only logged.
         */
        if (status === "completed") {
            try {
                await incrementCompletedOrders(order.userId);
            } catch (referralError) {
                console.error(
                    `[ORDERS] completeOrder: could not update completed-order count for order ${order.orderNumber}:`,
                    referralError
                );
            }

            /*
             * Referral reward: count this order for the referrer. Every 50
             * completed orders of a tier pay the referrer's reward.
             * Also only logged on failure, so the completion is never undone.
             */
            try {
                await recordReferralOrderCompleted(order);
            } catch (rewardError) {
                console.error(
                    `[ORDERS] completeOrder: could not record referral reward progress for order ${order.orderNumber}:`,
                    rewardError
                );
            }
        }

        return res.json({
            success: true,
            message: `Order marked ${status}. Active request removed; history preserved.`,
            order: adminOrder(order)
        });
    } catch (error) {
        return handleError(
            res,
            "completeOrder",
            error,
            "Unable to complete this order."
        );
    }
}
/**
 * ============================================================
 * ShadowSMM Backend
 * Funds Controller
 * ============================================================
 *
 * Module system: ES Modules
 * Database: MongoDB Native Driver
 *
 * Features:
 * - UPI deposit requests in INR
 * - Binance deposit requests in USD
 * - Cloudinary payment screenshot uploads
 * - Admin approval and rejection
 * - Live USD/INR conversion for UPI approvals
 * - Permanent transaction/audit history
 * - User-facing history (pending requests + approved/rejected transactions)
 * - In-app notifications
 * - Pending request deletion after review
 * - MongoDB transaction-based balance crediting
 *
 * IMPORTANT:
 * - Assumes users.balance is the user's USD balance.
 * - Requires MongoDB transactions (replica set / Atlas).
 * - The upload route must use Multer memoryStorage().
 * ============================================================
 */

import {
    ObjectId
} from "mongodb";

import {
    connectDB,
    getUsersCollection
} from "../config/db.js";

import {
    convertInrToUsd
} from "../services/currencyService.js";

import {
    uploadPaymentScreenshot
} from "../services/cloudinaryService.js";

import { sendTelegramMessage } from "../services/telegramService.js";

/**
 * ============================================================
 * Constants
 * ============================================================
 */

const MIN_UPI_AMOUNT = 10;
const MIN_BINANCE_AMOUNT = 1;
const MAX_AMOUNT = 1_000_000;

const MAX_SCREENSHOT_SIZE = 5 * 1024 * 1024;

const UTR_PATTERN = /^[A-Za-z0-9]{10,30}$/;
const TX_HASH_PATTERN = /^[A-Za-z0-9]{8,160}$/;

const COLLECTIONS = {
    requests: "fund_requests",
    transactions: "transactions",
    notifications: "notifications"
};

/**
 * ============================================================
 * Helpers
 * ============================================================
 */

function sendError(res, status, message) {
    return res.status(status).json({
        success: false,
        message,
        timestamp: new Date().toISOString()
    });
}

function parseObjectId(value) {
    if (!value || !ObjectId.isValid(String(value))) {
        return null;
    }

    return new ObjectId(String(value));
}

function getAuthenticatedUserId(req) {
    const payload = req.user;

    if (!payload || typeof payload !== "object") {
        return null;
    }

    return parseObjectId(
        payload.userId ??
        payload.id ??
        payload._id ??
        payload.sub
    );
}

function getAuthenticatedAdminId(req) {
    if (req.user?.role !== "admin") {
        return null;
    }

    return getAuthenticatedUserId(req);
}

function parseAmount(value) {
    if (
        value === undefined ||
        value === null ||
        String(value).trim() === ""
    ) {
        return null;
    }

    const amount = Number(value);

    if (
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > MAX_AMOUNT
    ) {
        return null;
    }

    return Math.round(
        (amount + Number.EPSILON) * 100
    ) / 100;
}

function normalizeText(value, maxLength = 200) {
    if (typeof value !== "string") {
        return "";
    }

    return value.trim().slice(0, maxLength);
}

function normalizeNetwork(value) {
    const network = normalizeText(value, 30).toLowerCase();

    const allowedNetworks = [
        "bep20",
        "trc20",
        "binance_id"
    ];

    return allowedNetworks.includes(network)
        ? network
        : null;
}

function isValidScreenshot(file) {
    if (!file) {
        return false;
    }

    if (
        !Buffer.isBuffer(file.buffer) ||
        file.buffer.length === 0 ||
        file.buffer.length > MAX_SCREENSHOT_SIZE
    ) {
        return false;
    }

    return true;
}

function getCollections(db) {
    return {
        requests: db.collection(COLLECTIONS.requests),
        transactions: db.collection(COLLECTIONS.transactions),
        notifications: db.collection(COLLECTIONS.notifications)
    };
}

async function ensureIndexes(collections) {
    await Promise.all([
        collections.requests.createIndex(
            { userId: 1, createdAt: -1 },
            { name: "fund_requests_user_created" }
        ),

        collections.requests.createIndex(
            { status: 1, createdAt: -1 },
            { name: "fund_requests_status_created" }
        ),

        collections.requests.createIndex(
            { utr: 1 },
            {
                unique: true,
                partialFilterExpression: {
                    utr: { $type: "string" }
                },
                name: "fund_requests_unique_utr"
            }
        ),

        collections.requests.createIndex(
            { txHash: 1 },
            {
                unique: true,
                partialFilterExpression: {
                    txHash: { $type: "string" }
                },
                name: "fund_requests_unique_tx_hash"
            }
        ),

        collections.transactions.createIndex(
            { userId: 1, createdAt: -1 },
            { name: "transactions_user_created" }
        ),

        collections.transactions.createIndex(
            { requestId: 1 },
            {
                unique: true,
                name: "transactions_unique_request"
            }
        ),

        collections.notifications.createIndex(
            { userId: 1, createdAt: -1 },
            { name: "notifications_user_created" }
        )
    ]);
}

function toPublicRequest(request) {
    return {
        id: String(request._id),
        userId: String(request.userId),
        username: request.username,
        method: request.method,
        amount: request.amount,
        currency: request.currency,
        utr: request.utr ?? null,
        network: request.network ?? null,
        txHash: request.txHash ?? null,
        screenshotUrl: request.screenshotUrl ?? null,
        status: request.status,
        createdAt: request.createdAt
    };
}

function toPublicTransaction(tx) {
    return {
        id: String(tx._id),
        requestId: tx.requestId ? String(tx.requestId) : null,

        // Readable ids for wallet entries (ORD-..., REF-..., RWD-...); null for deposits.
        transactionId: tx.transactionId ?? null,
        orderNumber: tx.orderNumber ?? null,

        type: tx.type,
        method: tx.method,
        amount: tx.amount,
        currency: tx.currency,
        creditAmount: tx.creditAmount ?? null,
        balanceBefore: tx.balanceBefore ?? null,
        balanceAfter: tx.balanceAfter ?? null,
        utr: tx.utr ?? null,
        network: tx.network ?? null,
        txHash: tx.txHash ?? null,
        status: tx.status, // "approved" | "rejected"
        createdAt: tx.createdAt
    };
}

function createNotification({
    userId,
    title,
    message,
    type,
    metadata = {}
}) {
    return {
        userId,
        title,
        message,
        type,
        metadata,
        read: false,
        createdAt: new Date()
    };
}

function getMongoSession(db) {
    if (!db.client?.startSession) {
        throw new Error(
            "MongoDB client session is unavailable. Check the database connection setup."
        );
    }

    return db.client.startSession();
}

/**
 * ============================================================
 * POST /api/funds/upi
 * Create a UPI deposit request
 * ============================================================
 */

export async function createUpiRequest(req, res) {
    try {
        const userId = getAuthenticatedUserId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "A valid user authentication token is required."
            );
        }

        const amount = parseAmount(req.body?.amount);

        if (amount === null || amount < MIN_UPI_AMOUNT) {
            return sendError(
                res,
                400,
                `Minimum UPI deposit is INR ${MIN_UPI_AMOUNT}.`
            );
        }

        const utr = normalizeText(req.body?.utr, 30);

        if (!UTR_PATTERN.test(utr)) {
            return sendError(
                res,
                400,
                "Enter a valid UTR/reference number."
            );
        }

        const db = await connectDB();
        const users = await getUsersCollection();
        const collections = getCollections(db);

        await ensureIndexes(collections);

        const user = await users.findOne(
            { _id: userId },
            { projection: { username: 1, email: 1 } }
        );

        if (!user) {
            return sendError(res, 404, "User not found.");
        }

        const existing = await collections.requests.findOne({
            utr
        });

        if (existing) {
            return sendError(
                res,
                409,
                "This UTR has already been submitted."
            );
        }

        const now = new Date();

        const request = {
            userId,
            username: user.username || "",
            method: "upi",
            amount,
            currency: "INR",
            utr,
            status: "pending",
            createdAt: now,
            updatedAt: now
        };

        const result = await collections.requests.insertOne(request);

        /*
         * Telegram admin notification (non-blocking).
         * Sent only after the request was saved. A Telegram failure is only
         * logged and never affects the response below.
         */
        try {
            void sendTelegramMessage(
                [
                    "💰 NEW SHADOWSMM FUNDS REQUEST",
                    "",
                    "Method: UPI",
                    `User: ${request.username}`,
                    `User ID: ${String(request.userId)}`,
                    `Amount: ₹${Number(request.amount).toFixed(2)}`,
                    `UTR: ${request.utr}`,
                    "Status: Pending",
                    `Time: ${new Date().toISOString()}`
                ].join("\n")
            ).catch((telegramError) => {
                console.error(
                    "[FUNDS] UPI Telegram notification failed:",
                    telegramError?.message || telegramError
                );
            });
        } catch (telegramError) {
            console.error(
                "[FUNDS] UPI Telegram notification could not be sent:",
                telegramError?.message || telegramError
            );
        }

        return res.status(201).json({
            success: true,
            message: "UPI deposit request submitted for verification.",
            request: {
                ...toPublicRequest({
                    ...request,
                    _id: result.insertedId
                })
            }
        });
    } catch (error) {
        if (error?.code === 11000) {
            return sendError(
                res,
                409,
                "This UTR has already been submitted."
            );
        }

        console.error("[FUNDS] UPI request error:", error);

        return sendError(
            res,
            500,
            "Unable to submit the UPI deposit request."
        );
    }
}

/**
 * ============================================================
 * POST /api/funds/crypto
 * Create a Binance deposit request
 *
 * Requires:
 * - Multer memoryStorage()
 * - req.file for screenshot, when supplied
 * - network and amount in req.body
 * ============================================================
 */

export async function createCryptoRequest(req, res) {
    try {
        const userId = getAuthenticatedUserId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "A valid user authentication token is required."
            );
        }

        const amount = parseAmount(req.body?.amount);

        if (
            amount === null ||
            amount < MIN_BINANCE_AMOUNT
        ) {
            return sendError(
                res,
                400,
                `Minimum Binance deposit is USD ${MIN_BINANCE_AMOUNT}.`
            );
        }

        const network = normalizeNetwork(req.body?.network);

        if (!network) {
            return sendError(
                res,
                400,
                "Select a supported Binance network."
            );
        }

        const txHash = normalizeText(
            req.body?.txHash,
            160
        );

        if (txHash && !TX_HASH_PATTERN.test(txHash)) {
            return sendError(
                res,
                400,
                "The transaction ID format is invalid."
            );
        }

        const screenshot = req.file || null;

        if (!txHash && !screenshot) {
            return sendError(
                res,
                400,
                "Provide a transaction ID or payment screenshot."
            );
        }

        if (screenshot && !isValidScreenshot(screenshot)) {
            return sendError(
                res,
                400,
                "Screenshot must be a valid image no larger than 5 MB."
            );
        }

        const db = await connectDB();
        const users = await getUsersCollection();
        const collections = getCollections(db);

        await ensureIndexes(collections);

        const user = await users.findOne(
            { _id: userId },
            { projection: { username: 1, email: 1 } }
        );

        if (!user) {
            return sendError(res, 404, "User not found.");
        }

        if (txHash) {
            const existing = await collections.requests.findOne({
                txHash
            });

            if (existing) {
                return sendError(
                    res,
                    409,
                    "This transaction ID has already been submitted."
                );
            }

            const processed = await collections.transactions.findOne({
                txHash
            });

            if (processed) {
                return sendError(
                    res,
                    409,
                    "This transaction ID has already been processed."
                );
            }
        }

        let uploadedImage = null;

        if (screenshot) {
            uploadedImage = await uploadPaymentScreenshot(
                screenshot.buffer,
                screenshot.mimetype
            );
        }

        const now = new Date();

        const request = {
            userId,
            username: user.username || "",
            method: "binance",
            amount,
            currency: "USD",
            network,
            status: "pending",
            createdAt: now,
            updatedAt: now
        };

        if (txHash) {
            request.txHash = txHash;
        }

        if (uploadedImage) {
            request.screenshotUrl = uploadedImage.url;
            request.screenshotPublicId = uploadedImage.publicId;
            request.screenshotFormat = uploadedImage.format;
        }

        const result = await collections.requests.insertOne(request);

        /*
         * Telegram admin notification (non-blocking).
         * Sent only after the request was saved. A Telegram failure is only
         * logged and never affects the response below.
         */
        try {
            void sendTelegramMessage(
                [
                    "💰 NEW SHADOWSMM FUNDS REQUEST",
                    "",
                    "Method: Binance",
                    `User: ${request.username}`,
                    `User ID: ${String(request.userId)}`,
                    `Amount: $${Number(request.amount).toFixed(2)} USD`,
                    `Network: ${request.network}`,
                    `Transaction ID: ${request.txHash || "Not provided"}`,
                    `Screenshot: ${request.screenshotUrl || "Not provided"}`,
                    "Status: Pending",
                    `Time: ${new Date().toISOString()}`
                ].join("\n")
            ).catch((telegramError) => {
                console.error(
                    "[FUNDS] Binance Telegram notification failed:",
                    telegramError?.message || telegramError
                );
            });
        } catch (telegramError) {
            console.error(
                "[FUNDS] Binance Telegram notification could not be sent:",
                telegramError?.message || telegramError
            );
        }

        return res.status(201).json({
            success: true,
            message: "Binance deposit request submitted for verification.",
            request: toPublicRequest({
                ...request,
                _id: result.insertedId
            })
        });
    } catch (error) {
        if (error?.code === 11000) {
            return sendError(
                res,
                409,
                "This UTR or transaction ID has already been submitted."
            );
        }

        console.error("[FUNDS] Binance request error:", error);

        return sendError(
            res,
            500,
            "Unable to submit the Binance deposit request."
        );
    }
}

/**
 * ============================================================
 * GET /api/funds/my-requests
 * User's pending requests
 * ============================================================
 */

export async function getMyFundRequests(req, res) {
    try {
        const userId = getAuthenticatedUserId(req);

        if (!userId) {
            return sendError(res, 401, "Authentication required.");
        }

        const db = await connectDB();
        const collections = getCollections(db);

        const requests = await collections.requests
            .find({ userId })
            .sort({ createdAt: -1 })
            .limit(100)
            .toArray();

        return res.status(200).json({
            success: true,
            requests: requests.map(toPublicRequest)
        });
    } catch (error) {
        console.error("[FUNDS] User requests error:", error);

        return sendError(
            res,
            500,
            "Unable to load your deposit requests."
        );
    }
}

/**
 * ============================================================
 * GET /api/funds/my-transactions
 * User's reviewed deposits (approved / rejected)
 * ============================================================
 */

export async function getMyTransactions(req, res) {
    try {
        const userId = getAuthenticatedUserId(req);

        if (!userId) {
            return sendError(res, 401, "Authentication required.");
        }

        const db = await connectDB();
        const collections = getCollections(db);

        const transactions = await collections.transactions
            .find({ userId })
            .sort({ createdAt: -1 })
            .limit(200)
            .toArray();

        return res.status(200).json({
            success: true,
            transactions: transactions.map(toPublicTransaction)
        });
    } catch (error) {
        console.error("[FUNDS] User transactions error:", error);

        return sendError(
            res,
            500,
            "Unable to load your transaction history."
        );
    }
}

/**
 * ============================================================
 * GET /api/funds/admin
 * Admin: list pending deposit requests
 * ============================================================
 */

export async function getFundRequests(req, res) {
    try {
        const adminId = getAuthenticatedAdminId(req);

        if (!adminId) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const db = await connectDB();
        const collections = getCollections(db);

        const status = normalizeText(
            req.query?.status || "pending",
            20
        );

        const allowedStatuses = [
            "pending",
            "all"
        ];

        if (!allowedStatuses.includes(status)) {
            return sendError(
                res,
                400,
                "Unsupported request filter."
            );
        }

        const filter = status === "all"
            ? {}
            : { status: "pending" };

        const requests = await collections.requests
            .find(filter)
            .sort({ createdAt: -1 })
            .limit(500)
            .toArray();

        return res.status(200).json({
            success: true,
            requests: requests.map(toPublicRequest)
        });
    } catch (error) {
        console.error("[FUNDS] Admin list error:", error);

        return sendError(
            res,
            500,
            "Unable to load deposit requests."
        );
    }
}

/**
 * ============================================================
 * PATCH /api/funds/admin/:id/approve
 * Approve request and credit the USD balance
 *
 * UPI:
 * INR amount -> live USD/INR conversion -> USD credit
 *
 * Binance:
 * USD amount -> direct USD credit
 *
 * Request deletion, balance update, transaction record and
 * notification are performed in one MongoDB transaction.
 * ============================================================
 */

export async function approveFundRequest(req, res) {
    let session;

    try {
        const adminId = getAuthenticatedAdminId(req);

        if (!adminId) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const requestId = parseObjectId(req.params?.id);

        if (!requestId) {
            return sendError(
                res,
                400,
                "Invalid deposit request ID."
            );
        }

        const db = await connectDB();
        const users = await getUsersCollection();
        const collections = getCollections(db);

        await ensureIndexes(collections);

        // Read the request to determine the conversion required.
        const initialRequest = await collections.requests.findOne({
            _id: requestId,
            status: "pending"
        });

        if (!initialRequest) {
            return sendError(
                res,
                404,
                "Pending deposit request not found. It may already have been processed."
            );
        }

        let conversion = null;
        let creditAmount;

        if (initialRequest.method === "upi") {
            // Fetch a fresh rate for this approval.
            conversion = await convertInrToUsd(
                initialRequest.amount,
                { forceRefresh: true }
            );

            creditAmount = conversion.convertedAmount;
        } else if (initialRequest.method === "binance") {
            creditAmount = initialRequest.amount;
        } else {
            return sendError(
                res,
                400,
                "Unsupported deposit method."
            );
        }

        session = getMongoSession(db);

        let outcome = null;

        await session.withTransaction(async () => {
            const request = await collections.requests.findOne(
                {
                    _id: requestId,
                    status: "pending"
                },
                { session }
            );

            if (!request) {
                throw new Error("FUND_REQUEST_ALREADY_PROCESSED");
            }

            // Reserve this request so concurrent approvals cannot
            // both credit the same request.
            const reservation = await collections.requests.updateOne(
                {
                    _id: requestId,
                    status: "pending"
                },
                {
                    $set: {
                        status: "processing",
                        processingBy: adminId,
                        processingAt: new Date(),
                        updatedAt: new Date()
                    }
                },
                { session }
            );

            if (reservation.modifiedCount !== 1) {
                throw new Error("FUND_REQUEST_ALREADY_PROCESSED");
            }

            const user = await users.findOne(
                { _id: request.userId },
                { session }
            );

            if (!user) {
                throw new Error("FUND_USER_NOT_FOUND");
            }

            // This controller assumes users.balance stores USD.
            const balanceBefore = Number(user.balance ?? 0);

            if (
                !Number.isFinite(balanceBefore) ||
                balanceBefore < 0
            ) {
                throw new Error("FUND_USER_BALANCE_INVALID");
            }

            const balanceAfter =
                Math.round(
                    (balanceBefore + creditAmount + Number.EPSILON) * 100
                ) / 100;

            const balanceUpdate = await users.updateOne(
                { _id: request.userId },
                { $inc: { balance: creditAmount } },
                { session }
            );

            if (balanceUpdate.modifiedCount !== 1) {
                throw new Error("FUND_BALANCE_UPDATE_FAILED");
            }

            const now = new Date();

            // Insert permanent audit/transaction record.
            await collections.transactions.insertOne(
                {
                    requestId: request._id,
                    userId: request.userId,
                    username: request.username,
                    adminId,
                    type: "deposit",
                    method: request.method,
                    amount: request.amount,
                    currency: request.currency,
                    creditAmount,
                    creditCurrency: "USD",
                    balanceBefore,
                    balanceAfter,
                    utr: request.utr ?? null,
                    network: request.network ?? null,
                    txHash: request.txHash ?? null,
                    screenshotUrl: request.screenshotUrl ?? null,
                    status: "approved",
                    exchangeRate: conversion?.exchangeRate ?? null,
                    rateSource: conversion?.rateSource ?? null,
                    rateFetchedAt: conversion?.rateFetchedAt ?? null,
                    providerUpdatedAt:
                        conversion?.providerUpdatedAt ?? null,
                    createdAt: now
                },
                { session }
            );

            // User notification.
            await collections.notifications.insertOne(
                createNotification({
                    userId: request.userId,
                    title: "Deposit approved",
                    message:
                        request.method === "upi"
                            ? `Your INR ${request.amount.toFixed(2)} deposit was approved. $${creditAmount.toFixed(2)} has been added to your balance.`
                            : `Your Binance deposit of $${creditAmount.toFixed(2)} was approved.`,
                    type: "fund_approved",
                    metadata: {
                        requestId: String(request._id),
                        method: request.method,
                        amount: request.amount,
                        currency: request.currency,
                        creditedAmount: creditAmount,
                        creditedCurrency: "USD"
                    }
                }),
                { session }
            );

            // Delete the pending request only after recording its
            // transaction and notification within this transaction.
            const deletion = await collections.requests.deleteOne(
                {
                    _id: request._id,
                    status: "processing",
                    processingBy: adminId
                },
                { session }
            );

            if (deletion.deletedCount !== 1) {
                throw new Error("FUND_REQUEST_DELETE_FAILED");
            }

            outcome = {
                requestId: String(request._id),
                method: request.method,
                originalAmount: request.amount,
                originalCurrency: request.currency,
                creditedAmount: creditAmount,
                creditedCurrency: "USD",
                exchangeRate: conversion?.exchangeRate ?? null,
                balanceAfter
            };
        });

        return res.status(200).json({
            success: true,
            message: "Deposit approved and balance credited.",
            result: outcome
        });
    } catch (error) {
        if (error?.message === "FUND_REQUEST_ALREADY_PROCESSED") {
            return sendError(
                res,
                409,
                "This request has already been processed."
            );
        }

        if (error?.message === "FUND_USER_NOT_FOUND") {
            return sendError(res, 404, "Deposit user not found.");
        }

        if (error?.message === "FUND_USER_BALANCE_INVALID") {
            return sendError(
                res,
                500,
                "The user's current balance is invalid."
            );
        }

        if (error?.message === "FUND_BALANCE_UPDATE_FAILED") {
            return sendError(
                res,
                500,
                "Could not update the user's balance."
            );
        }

        if (error?.message === "FUND_REQUEST_DELETE_FAILED") {
            return sendError(
                res,
                500,
                "Could not finalize the deposit request."
            );
        }

        console.error("[FUNDS] Approval error:", error);

        return sendError(
            res,
            503,
            "Deposit approval failed. Verify the database and exchange-rate service before retrying."
        );
    } finally {
        if (session) {
            await session.endSession();
        }
    }
}

/**
 * ============================================================
 * PATCH /api/funds/admin/:id/reject
 * Reject request, delete it and notify user.
 *
 * No balance changes are made.
 * Rejection history is permanently saved.
 * ============================================================
 */

export async function rejectFundRequest(req, res) {
    let session;

    try {
        const adminId = getAuthenticatedAdminId(req);

        if (!adminId) {
            return sendError(
                res,
                403,
                "Administrator access required."
            );
        }

        const requestId = parseObjectId(req.params?.id);

        if (!requestId) {
            return sendError(
                res,
                400,
                "Invalid deposit request ID."
            );
        }

        const db = await connectDB();
        const collections = getCollections(db);

        await ensureIndexes(collections);

        session = getMongoSession(db);

        let outcome = null;

        await session.withTransaction(async () => {
            const request = await collections.requests.findOne(
                {
                    _id: requestId,
                    status: "pending"
                },
                { session }
            );

            if (!request) {
                throw new Error("FUND_REQUEST_ALREADY_PROCESSED");
            }

            const reservation = await collections.requests.updateOne(
                {
                    _id: requestId,
                    status: "pending"
                },
                {
                    $set: {
                        status: "processing",
                        processingBy: adminId,
                        processingAt: new Date(),
                        updatedAt: new Date()
                    }
                },
                { session }
            );

            if (reservation.modifiedCount !== 1) {
                throw new Error("FUND_REQUEST_ALREADY_PROCESSED");
            }

            const now = new Date();

            await collections.transactions.insertOne(
                {
                    requestId: request._id,
                    userId: request.userId,
                    username: request.username,
                    adminId,
                    type: "deposit",
                    method: request.method,
                    amount: request.amount,
                    currency: request.currency,
                    utr: request.utr ?? null,
                    network: request.network ?? null,
                    txHash: request.txHash ?? null,
                    screenshotUrl: request.screenshotUrl ?? null,
                    status: "rejected",
                    balanceChanged: false,
                    createdAt: now
                },
                { session }
            );

            await collections.notifications.insertOne(
                createNotification({
                    userId: request.userId,
                    title: "Deposit rejected",
                    message:
                        "Your deposit request was rejected. No balance was added. Please contact support if you believe this is incorrect.",
                    type: "fund_rejected",
                    metadata: {
                        requestId: String(request._id),
                        method: request.method,
                        amount: request.amount,
                        currency: request.currency
                    }
                }),
                { session }
            );

            const deletion = await collections.requests.deleteOne(
                {
                    _id: request._id,
                    status: "processing",
                    processingBy: adminId
                },
                { session }
            );

            if (deletion.deletedCount !== 1) {
                throw new Error("FUND_REQUEST_DELETE_FAILED");
            }

            outcome = {
                requestId: String(request._id),
                status: "rejected",
                balanceChanged: false
            };
        });

        return res.status(200).json({
            success: true,
            message: "Deposit rejected and request removed.",
            result: outcome
        });
    } catch (error) {
        if (error?.message === "FUND_REQUEST_ALREADY_PROCESSED") {
            return sendError(
                res,
                409,
                "This request has already been processed."
            );
        }

        if (error?.message === "FUND_REQUEST_DELETE_FAILED") {
            return sendError(
                res,
                500,
                "Could not finalize the deposit request."
            );
        }

        console.error("[FUNDS] Rejection error:", error);

        return sendError(
            res,
            500,
            "Unable to reject the deposit request."
        );
    } finally {
        if (session) {
            await session.endSession();
        }
    }
}

/**
 * ============================================================
 * Default Export
 * ============================================================
 */

export default {
    createUpiRequest,
    createCryptoRequest,
    getMyFundRequests,
    getMyTransactions,
    getFundRequests,
    approveFundRequest,
    rejectFundRequest
};
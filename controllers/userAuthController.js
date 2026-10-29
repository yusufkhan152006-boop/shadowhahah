import bcrypt from "bcryptjs";
import { randomBytes } from "node:crypto";
import { ObjectId } from "mongodb";
import { getUsersCollection } from "../config/db.js";
import { sign } from "../utils/jwt.js";
import { sendTelegramMessage } from "../services/telegramService.js";

/* -------------------------------------------------------------------------- */
/*  Constants                                                                 */
/* -------------------------------------------------------------------------- */

const LOG_PREFIX = "[USER AUTH]";

const BCRYPT_ROUNDS = 12;
const MAX_PASSWORD_BYTES = 72; // bcrypt silently truncates anything beyond this
const MIN_PASSWORD_LENGTH = 8;

const MAX_EMAIL_LENGTH = 254;
const MAX_REFERRAL_ATTEMPTS = 5;
const MONGO_DUPLICATE_KEY = 11000;

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const WHATSAPP_RE = /^\+?[0-9]{8,15}$/;
const OBJECT_ID_RE = /^[a-f\d]{24}$/i;

const INVALID_CREDENTIALS_MSG = "Invalid username/email or password.";

/**
 * Pre-computed hash used to keep login timing consistent when the user does
 * not exist. This prevents attackers from discovering valid accounts by
 * measuring response times.
 */
const DUMMY_HASH = bcrypt.hashSync("timing-attack-protection", BCRYPT_ROUNDS);

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

/** Returns only the fields that are safe to expose to the client. */
function publicUser(user) {
    return {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        whatsapp: user.whatsapp,
        role: user.role,
        balance: user.balance ?? 0,
        spent: user.spent ?? 0,
        completedOrders: user.completedOrders ?? 0,
        referralCode: user.referralCode,
        referredBy: user.referredBy ?? null,
        createdAt: user.createdAt
    };
}

/** Generates a referral code such as `S1A2B3C4DM`. */
function makeReferralCode() {
    return `S${randomBytes(4).toString("hex").toUpperCase()}M`;
}

/** Sends a consistent error response. */
function sendError(res, status, message, errors = undefined) {
    return res.status(status).json({
        success: false,
        message,
        ...(errors ? { errors } : {})
    });
}

/** Removes spaces, brackets and hyphens from a phone number. */
function cleanWhatsApp(value) {
    return String(value ?? "").replace(/[\s()-]/g, "");
}

/** Safely converts any input into a trimmed string. */
function toTrimmedString(value) {
    return String(value ?? "").trim();
}

/** Byte length matters for bcrypt, not character count. */
function exceedsPasswordByteLimit(password) {
    return Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES;
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= MIN_PASSWORD_LENGTH &&
        !exceedsPasswordByteLimit(password)
    );
}

/** Builds the JWT payload in one place so register/login stay consistent. */
function buildTokenPayload(user) {
    const id = user._id.toString();

    return {
        sub: id,
        userId: id,
        username: user.username,
        role: user.role
    };
}

/** Validates the registration fields and returns an errors object. */
function validateRegistration({ username, email, whatsapp, password }) {
    const errors = {};

    if (!USERNAME_RE.test(username)) {
        errors.username =
            "Username must be 3–30 characters using letters, numbers, dots, underscores or hyphens.";
    }

    if (email.length > MAX_EMAIL_LENGTH || !EMAIL_RE.test(email)) {
        errors.email = "Enter a valid email address.";
    }

    if (!WHATSAPP_RE.test(whatsapp)) {
        errors.whatsapp = "Enter a valid WhatsApp number.";
    }

    if (!validPassword(password)) {
        errors.password =
            "Password must be at least 8 characters and no more than 72 UTF-8 bytes.";
    }

    return errors;
}

/* -------------------------------------------------------------------------- */
/*  Controllers                                                               */
/* -------------------------------------------------------------------------- */

/**
 * POST /register
 * Creates a new user account and returns a JWT.
 */
export async function register(req, res) {
    try {
        const username = toTrimmedString(req.body?.username);
        const usernameLower = username.toLowerCase();
        const email = toTrimmedString(req.body?.email).toLowerCase();
        const whatsapp = cleanWhatsApp(req.body?.whatsapp);
        const password = req.body?.password;

        const errors = validateRegistration({ username, email, whatsapp, password });

        if (Object.keys(errors).length) {
            return sendError(res, 422, "Please correct the form fields.", errors);
        }

        const users = await getUsersCollection();

        // Fast pre-check for a friendlier error message.
        const existing = await users.findOne({
            $or: [{ usernameLower }, { email }]
        });

        if (existing) {
            const field = existing.email === email ? "email" : "username";

            return sendError(
                res,
                409,
                field === "email"
                    ? "This email is already registered."
                    : "This username is already taken.",
                { [field]: "Already registered." }
            );
        }

        // Store only a bcrypt hash. Never store the actual password.
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const now = new Date();
        let user;
        let inserted;

        // Retry if a randomly generated referral code collides.
        for (let attempt = 1; attempt <= MAX_REFERRAL_ATTEMPTS; attempt++) {
            user = {
                username,
                usernameLower,
                email,
                whatsapp,
                passwordHash,
                role: "user",
                balance: 0,
                completedOrders: 0,
                spent: 0,
                referralCode: makeReferralCode(),
                referredBy: null,
                isActive: true,
                createdAt: now,
                updatedAt: now,
                lastLoginAt: now
            };

            try {
                inserted = await users.insertOne(user);
                break;
            } catch (error) {
                if (error?.code !== MONGO_DUPLICATE_KEY) throw error;

                // Race condition: someone registered the same username/email
                // between our pre-check and the insert, or the referral code collided.
                const duplicate = await users.findOne({
                    $or: [
                        { usernameLower },
                        { email },
                        { referralCode: user.referralCode }
                    ]
                });

                if (duplicate?.usernameLower === usernameLower) {
                    return sendError(res, 409, "This username is already taken.", {
                        username: "Already registered."
                    });
                }

                if (duplicate?.email === email) {
                    return sendError(res, 409, "This email is already registered.", {
                        email: "Already registered."
                    });
                }

                if (attempt === MAX_REFERRAL_ATTEMPTS) throw error;
            }
        }

        if (!inserted || !user) {
            return sendError(res, 500, "Could not create the account.");
        }

        user._id = inserted.insertedId;

        /*
         * Telegram admin notification (non-blocking).
         * Sent only after the user was saved. Never includes the password,
         * password hash or JWT. A Telegram failure is only logged and never
         * affects the registration response.
         */
        try {
            const telegramMessage = [
                "🆕 NEW SHADOWSMM ACCOUNT",
                `Username: ${user.username}`,
                `Email: ${user.email}`,
                `WhatsApp: ${user.whatsapp}`,
                `User ID: ${user._id.toString()}`,
                `Referral Code: ${user.referralCode}`,
                `Role: ${user.role}`,
                `Time: ${new Date().toISOString()}`
            ].join("\n");

            void sendTelegramMessage(telegramMessage).catch((error) => {
                console.error(
                    `${LOG_PREFIX} Telegram notification error:`,
                    error?.message || error
                );
            });
        } catch (error) {
            console.error(
                `${LOG_PREFIX} Telegram notification could not be sent:`,
                error?.message || error
            );
        }

        const token = await sign(buildTokenPayload(user));

        return res.status(201).json({
            success: true,
            message: "Account created successfully.",
            token,
            user: publicUser(user)
        });
    } catch (error) {
        console.error(`${LOG_PREFIX} Register error:`, error);
        return sendError(res, 500, "Unable to create account right now.");
    }
}

/**
 * POST /login
 * Authenticates with username or email and returns a JWT.
 */
export async function login(req, res) {
    try {
        const identifier = toTrimmedString(
            req.body?.username ?? req.body?.identifier
        );
        const password = req.body?.password;

        if (!identifier || typeof password !== "string" || !password) {
            return sendError(res, 422, "Username/email and password are required.");
        }

        if (exceedsPasswordByteLimit(password)) {
            return sendError(res, 401, INVALID_CREDENTIALS_MSG);
        }

        const users = await getUsersCollection();
        const normalized = identifier.toLowerCase();

        const user = await users.findOne({
            $or: [{ usernameLower: normalized }, { email: normalized }]
        });

        // Always run bcrypt.compare, even for unknown users, so response time
        // does not reveal whether an account exists.
        const matches = await bcrypt.compare(
            password,
            user?.passwordHash ?? DUMMY_HASH
        );

        if (!user || !user.passwordHash || !matches) {
            return sendError(res, 401, INVALID_CREDENTIALS_MSG);
        }

        // Checked only after the password is verified, so disabled-account
        // status is never leaked to someone without valid credentials.
        if (user.isActive === false) {
            return sendError(res, 403, "This account is disabled. Contact support.");
        }

        const now = new Date();

        await users.updateOne(
            { _id: user._id },
            { $set: { lastLoginAt: now, updatedAt: now } }
        );

        const token = await sign(buildTokenPayload(user));

        return res.json({
            success: true,
            message: "Login successful.",
            token,
            user: publicUser({ ...user, lastLoginAt: now })
        });
    } catch (error) {
        console.error(`${LOG_PREFIX} Login error:`, error);
        return sendError(res, 500, "Unable to log in right now.");
    }
}

/**
 * GET /me
 * Returns the currently authenticated user.
 */
export async function me(req, res) {
    try {
        const id = req.user?.sub ?? req.user?.userId;

        if (typeof id !== "string" || !OBJECT_ID_RE.test(id)) {
            return sendError(res, 401, "Invalid authentication token.");
        }

        const users = await getUsersCollection();
        const user = await users.findOne({ _id: new ObjectId(id) });

        if (!user || user.isActive === false) {
            return sendError(res, 401, "Account not found or disabled.");
        }

        return res.json({
            success: true,
            user: publicUser(user)
        });
    } catch (error) {
        console.error(`${LOG_PREFIX} Me error:`, error);
        return sendError(res, 500, "Unable to load account.");
    }
}

/**
 * POST /logout
 * JWT is stateless, so the frontend must remove `shadowsmm_token`.
 */
export async function logout(req, res) {
    return res.json({
        success: true,
        message: "Logged out. Clear the saved token on the frontend."
    });
}
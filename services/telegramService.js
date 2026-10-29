const TELEGRAM_API_BASE = "https://api.telegram.org";
const TELEGRAM_TIMEOUT_MS = 5000;

/**
 * Sends an admin notification through Telegram.
 *
 * Required environment variables:
 * TELEGRAM_BOT_TOKEN
 * TELEGRAM_CHAT_ID
 *
 * @param {string} message - Notification text to send.
 * @returns {Promise<boolean>} True if Telegram accepted the message.
 */
export async function sendTelegramMessage(message) {
    const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
    const chatId = process.env.TELEGRAM_CHAT_ID?.trim();

    // Validate configuration.
    if (!token || !chatId) {
        console.error(
            "[Telegram] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID."
        );
        return false;
    }

    // Validate message.
    if (typeof message !== "string" || !message.trim()) {
        console.error("[Telegram] Cannot send an empty or invalid message.");
        return false;
    }

    // Telegram sendMessage has a 4096-character message limit.
    const safeMessage = message.trim().slice(0, 4000);

    const controller = new AbortController();
    const timeout = setTimeout(
        () => controller.abort(),
        TELEGRAM_TIMEOUT_MS
    );

    try {
        const response = await fetch(
            `${TELEGRAM_API_BASE}/bot${token}/sendMessage`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: safeMessage,
                    disable_web_page_preview: true,
                }),
                signal: controller.signal,
            }
        );

        let result;

        try {
            result = await response.json();
        } catch {
            console.error(
                `[Telegram] Invalid API response. HTTP status: ${response.status}`
            );
            return false;
        }

        if (!response.ok || result?.ok !== true) {
            console.error(
                "[Telegram] Failed to send notification:",
                result?.description || `HTTP ${response.status}`
            );
            return false;
        }

        return true;
    } catch (error) {
        if (error?.name === "AbortError") {
            console.error("[Telegram] Request timed out.");
        } else {
            console.error(
                "[Telegram] Request error:",
                error?.message || "Unknown error"
            );
        }

        return false;
    } finally {
        clearTimeout(timeout);
    }
}
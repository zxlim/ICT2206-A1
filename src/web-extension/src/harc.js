/**
 * HTTP Authenticated Response Content (HARC):
 * Provides an additional layer of authentication through a Content Delivery Network.
 *
 * HARC Client-side Verifier Extension for Mozilla Firefox.
 *
 * @author     Daniel Tan Zhonghao  <2001240@sit.singaporetech.edu.sg>
 * @author     Ho Xiu Qi            <1802962@sit.singaporetech.edu.sg>
 * @author     Lim Zhao Xiang       <1802976@sit.singaporetech.edu.sg>
 * @copyright  Copyright (c) 2022. For the fulfillment of the SIT module
 *             ICT2206 Web Security (AY2021/2022, Trimester 2).
 */
/* eslint-disable no-console */

/**----------------------------------------------------------------
 * Constants.
 *----------------------------------------------------------------*/

// DEVELOPMENT USE ONLY.
const DEBUG = false;

const DIGEST_ALGO = "SHA-256";
const EC_CURVE = "P-256";
const EC_TYPE = "ECDSA";
const HARC_DNS_SUBDOMAIN = "_arc";
const HARC_HEADER_ALGO = "x-arc-algo";
const HARC_HEADER_DIGEST = "x-arc-digest";
const HARC_HEADER_SIGNATURE = "x-arc-signature";
const RESPONSE_MAP = new Map();
const VALIDATION_RESULT_MAP = new Map();
const VALIDATION_RESULT_MAP_LIMIT = 512;

// Text-like content with application prefix.
const APP_CONTENT_TYPE_TO_VERIFY = [
    "application/javascript",
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/atom+xml",
];

// Default selection of DOH servers.
const DOH_SERVER_CHOICES = new Map([
    ["cloudflare", "https://1.1.1.1/dns-query"],
    ["cloudflare-mozilla", "https://mozilla.cloudflare-dns.com/dns-query"],
    ["google", "https://dns.google/dns-query"],
    ["quad9", "https://9.9.9.9:5053/dns-query"],
]);

// Default DOH server: Cloudflare (Mozilla)
let DNS_DOH_RESOLVER = DOH_SERVER_CHOICES.get("cloudflare-mozilla");

/**----------------------------------------------------------------
 * Utility functions.
 *----------------------------------------------------------------*/

/**
 * Development debug logger.
 *
 * @function  logDebug
 * @param     {String}  msg  The message to log.
 */
const logDebug = (message) => {
    if (DEBUG === true) {
        console.debug(`[HARC] ${message}`);
    }
};

/**
 * Error logger.
 *
 * @function  logError
 * @param     {error}  error  The error thrown.
 */
const logError = (error) => {
    console.error(error.message);
    console.error(error.stack);
};

/**
 * Converts a String into a JavaScript ArrayBuffer object.
 *
 * @function  str2ab
 * @param     {String}  str  The string to convert.
 * @returns   {ArrayBuffer}  The ArrayBuffer instance.
 */
const str2ab = (str) => {
    const ab = new ArrayBuffer(str.length);
    const buffer = new Uint8Array(ab);

    for (let i = 0; i < str.length; ++i) {
        buffer[i] = str.charCodeAt(i);
    }

    return buffer;
};

/**
 * Validates whether a given DOH server is resolvable.
 *
 * @async
 * @function  validateDohServer
 * @param     {String}  addr  Address of the DOH server to validate.
 * @returns   {boolean}       Result of the operation.
 */
const validateDohServer = async (addr) => {
    try {
        const dnsHostname = new URL(addr).hostname;
        const result = await browser.dns.resolve(dnsHostname, ["bypass_cache"]);
        return result.addresses.length !== 0;
    } catch (error) {
        return false;
    }
};

/**
 * Set the DOH server to use.
 *
 * @async
 * @function  setDohServer
 * @param     {Object}  payload  A JavaScript object containing choice
 *                               and customDohServerAddr attributes.
 * @returns   {Object}           JavaScript object describing result of
 *                               the operation.
 */
const setDohServer = async (payload) => {
    const result = {
        success: true,
        message: "Preference saved.",
    };

    if (payload.choice === "custom") {
        const validated = await validateDohServer(payload.customDohServerAddr);

        if (validated) {
            DNS_DOH_RESOLVER = payload.customDohServerAddr;
            logDebug(`Saved DOH server preference: ${DNS_DOH_RESOLVER}`);
        } else {
            result.success = false;
            result.message = "Failed to resolve DOH server hostname.";
        }
    } else if (DOH_SERVER_CHOICES.has(payload.choice)) {
        DNS_DOH_RESOLVER = DOH_SERVER_CHOICES.get(payload.choice);
        logDebug(`Saved DOH server preference: ${payload.choice}`);
    } else {
        DNS_DOH_RESOLVER = DOH_SERVER_CHOICES.get("cloudflare-mozilla");
        result.success = false;
        result.message = "Unrecognised option selected.";
    }

    return result;
};

/**----------------------------------------------------------------
 * HARC Main Program Logic.
 *----------------------------------------------------------------*/

/**
 * Invoke the failure action.
 *
 * @function  invokeFailure
 * @param     {int}     tabId   The tab ID.
 * @param     {String}  action  The action to perform on failure.
 */
const invokeFailure = (tabId, action) => {
    browser.browserAction.setBadgeText({ tabId: tabId, text: "!" });

    if (action === "doh-failure") {
        browser.browserAction.setBadgeBackgroundColor({
            tabId: tabId,
            color: [217, 217, 41, 255],
        });
        VALIDATION_RESULT_MAP.set(tabId, "doh-failure");
    } else {
        let failureAction = "src/actions/warn.js";

        browser.browserAction.setBadgeBackgroundColor({
            tabId: tabId,
            color: [217, 0, 0, 255],
        });
        VALIDATION_RESULT_MAP.set(tabId, "untrusted");

        if (action === "enforce") {
            failureAction = "src/actions/block.js";
        }

        browser.tabs.executeScript({
            file: failureAction,
        });
    }
};

/**
 * A listener to capture the incoming response body content.
 * See: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/filterResponseData
 *
 * @function  captureResponseContent
 * @param     {details}  request  The request details.
 */
const captureResponseContent = (request) => {
    const decoder = new TextDecoder("utf-8");
    const responseChunks = [];
    const responseFilter = browser.webRequest.filterResponseData(
        request.requestId,
    );

    responseFilter.ondata = (event) => {
        // event.data is an ArrayBuffer.
        const chunk = decoder.decode(event.data, { stream: true });
        responseChunks.push(chunk);
        responseFilter.write(event.data);
    };

    // eslint-disable-next-line no-unused-vars
    responseFilter.onstop = (event) => {
        responseFilter.close();
        responseChunks.push(decoder.decode());
        RESPONSE_MAP.set(request.url, str2ab(responseChunks.join("")));
    };
};

/**
 * Query the DNS for the HARC action and public key of the domain.
 * Valid actions: ["warn", "enforce"]
 *
 * @async
 * @function  getHARCDNSPayload
 * @param     {URL}  url  The active URL.
 * @returns   {Array}     An array containing the action and public key.
 */
const getHARCDNSPayload = async (url) => {
    // eslint-disable-next-line no-undef
    const domain = psl.parse(url.hostname);
    const dnsQueryDomain = `${domain.subdomain}.${HARC_DNS_SUBDOMAIN}.${domain.domain}`;

    if (!(await validateDohServer(DNS_DOH_RESOLVER))) {
        logError({
            message: `Failed to resolve '${DNS_DOH_RESOLVER}'. Unable to proceed.`,
            stack: "No stack trace.",
        });
        return ["doh-failure", null];
    }

    // eslint-disable-next-line no-undef
    const resolver = new doh.DohResolver(DNS_DOH_RESOLVER);
    logDebug(`Querying DOH Server: ${DNS_DOH_RESOLVER}`);
    logDebug(`Querying TXT Record: ${dnsQueryDomain}`);

    try {
        const dnsResponse = await resolver.query(dnsQueryDomain, "TXT");

        if (dnsResponse.answers.length === 0) {
            // No such DNS record.
            return [null, null];
        }

        const payload = dnsResponse.answers[0].data.toString().split(";");

        switch (payload.length) {
            case 1:
                // Assume only public key in DNS record. Default to "warn" action.
                return ["warn", payload[0].trim()];
            case 2:
                // [action, publicKey]
                return [payload[0].trim().toLowerCase(), payload[1].trim()];
            default:
                // Invalid DNS record.
                return [null, null];
        }
    } catch (error) {
        logError(error);
        return ["doh-failure", null];
    }
};

/**
 * Validate the response content.
 *
 * @async
 * @function  verifyResponseContent
 * @param     {details}  response  The response details.
 */
const verifyResponseContent = async (response) => {
    browser.tabs
        .query({ currentWindow: true, active: true })
        .then(async (tabs) => {
            const tab = tabs[0];

            if (response.url !== tab.url) {
                // Not the main requested resource.
                return;
            }

            browser.browserAction.setBadgeText({ tabId: tab.id, text: "" });

            let contentType = "";
            let publicKey = null;
            let signature = null;

            response.responseHeaders.forEach((header) => {
                switch (header.name.toLowerCase()) {
                    case HARC_HEADER_ALGO:
                        logDebug(`Algorithm: ${header.value.trim()}`);
                        break;
                    case HARC_HEADER_DIGEST:
                        logDebug(`Digest: ${header.value.trim()}`);
                        break;
                    case HARC_HEADER_SIGNATURE:
                        try {
                            signature = str2ab(
                                window.atob(header.value.trim()),
                            );
                        } catch (error) {
                            logError(error);
                        }
                        break;
                    case "content-type":
                        contentType = header.value.trim();
                        break;
                    default:
                    // Do nothing.
                }
            });

            if (VALIDATION_RESULT_MAP.size > VALIDATION_RESULT_MAP_LIMIT) {
                // Don't want to store too many results, may hog up memory.
                VALIDATION_RESULT_MAP.clear();
            }

            if (
                !contentType.startsWith("text/") &&
                !APP_CONTENT_TYPE_TO_VERIFY.includes(contentType)
            ) {
                // Unsupported content type. Skip verification.
                logDebug(
                    `Skipping verification for '${response.url}': Unsupported content type '${contentType}'`,
                );
                VALIDATION_RESULT_MAP.set(tab.id, "ignored-resource");
                return;
            }

            const dnsPayload = await getHARCDNSPayload(new URL(response.url));
            const action = dnsPayload[0];
            const publicKeyDer = dnsPayload[1];

            if (signature === null) {
                if (action === null && publicKeyDer === null) {
                    // HARC is not enabled on this domain.
                    logDebug("HARC not enabled on this domain.");
                    VALIDATION_RESULT_MAP.set(tab.id, "ignored-domain");
                    return;
                }

                console.warn(`[HARC] Missing header: ${HARC_HEADER_SIGNATURE}`);
                invokeFailure(tab.id, action);
                return;
            }

            if (publicKeyDer === null) {
                console.warn(
                    "[HARC] Unable to retrieve public key. Cannot proceed with response content validation.",
                );
                invokeFailure(tab.id, action);
                return;
            }

            try {
                publicKey = await crypto.subtle.importKey(
                    "spki",
                    str2ab(window.atob(publicKeyDer)),
                    {
                        name: EC_TYPE,
                        namedCurve: EC_CURVE,
                    },
                    false,
                    ["verify"],
                );
            } catch (error) {
                // Error importing public key.
                logError(error);
                invokeFailure(tab.id, action);
                return;
            }

            // Wait up to 5 seconds for response content to be ready.
            for (let i = 0; i < 5; ++i) {
                if (RESPONSE_MAP.has(response.url)) {
                    break;
                }
                // Sleep for 1 second.
                // eslint-disable-next-line no-await-in-loop
                await new Promise((c) => {
                    setTimeout(c, 1000);
                });
            }

            if (!RESPONSE_MAP.has(response.url)) {
                console.error("[HARC] Failed to read response content.");
                invokeFailure(tab.id, action);
                return;
            }

            const signatureVerified = await crypto.subtle.verify(
                {
                    name: EC_TYPE,
                    hash: DIGEST_ALGO,
                },
                publicKey,
                signature,
                RESPONSE_MAP.get(response.url),
            );

            // Data stored in RESPONSE_MAP no longer needed.
            RESPONSE_MAP.delete(response.url);

            if (!signatureVerified) {
                console.error("[HARC] Signature validation failed!");
                invokeFailure(tab.id, action);
            } else {
                logDebug("Signature verified.");
                VALIDATION_RESULT_MAP.set(tab.id, "trusted");
            }
        })
        .catch((error) => {
            logError(error);
        });
};

/**
 * Extension entrypoint.
 *
 * @function  entrypoint
 */
const entrypoint = async () => {
    VALIDATION_RESULT_MAP.clear();

    browser.runtime.onMessage.addListener(async (message) => {
        logDebug(`Got message: ${JSON.stringify(message)}`);
        const result = {
            data: null,
        };

        let data;

        switch (message.type) {
            case "getDohPreference":
                data = {
                    choice: "custom",
                    customDohServerAddr: null,
                };

                // eslint-disable-next-line no-restricted-syntax
                for (const [key, value] of DOH_SERVER_CHOICES.entries()) {
                    if (value === DNS_DOH_RESOLVER) {
                        data.choice = key;
                        break;
                    }
                }

                if (data.choice === "custom") {
                    data.customDohServerAddr = DNS_DOH_RESOLVER;
                }

                result.data = data;
                break;
            case "setDohPreference":
                result.data = await setDohServer(message.data);
                break;
            case "harcValidationResult":
                result.data = VALIDATION_RESULT_MAP.get(message.tabId);
                break;
            default:
            // No default.
        }

        return result;
    });

    browser.webRequest.onBeforeRequest.addListener(
        captureResponseContent,
        { urls: ["<all_urls>"], types: ["main_frame"] },
        ["blocking"],
    );

    browser.webRequest.onCompleted.addListener(
        verifyResponseContent,
        { urls: ["<all_urls>"] },
        ["responseHeaders"],
    );
};

entrypoint();

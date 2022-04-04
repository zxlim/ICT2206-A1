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
const HARC_VALID_ACTIONS = ["enforce", "warn"];

const TAB_ACTION_MAP = new Map();
const TAB_RESPONSES_MAP = new Map();
const TAB_RESPONSES_ENCODING_MAP = new Map();
const VALIDATION_RESULT_MAP = new Map();

// Default selection of DOH servers.
// "disable" option disables HARC validation.
const DOH_SERVER_CHOICES = new Map([
    ["cloudflare", "https://1.1.1.1/dns-query"],
    ["cloudflare-mozilla", "https://mozilla.cloudflare-dns.com/dns-query"],
    ["google", "https://dns.google/dns-query"],
    ["quad9", "https://9.9.9.9:5053/dns-query"],
    ["disable", null],
]);

// Default DOH server: Cloudflare (Mozilla)
let DNS_DOH_RESOLVER = DOH_SERVER_CHOICES.get("cloudflare-mozilla");

/**----------------------------------------------------------------
 * Console Logging functions.
 *----------------------------------------------------------------*/

/**
 * Logger for debug messages, used in development only.
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
 * Logger for errors.
 *
 * @function  logError
 * @param     {error}  error  The error thrown.
 */
const logError = (error) => {
    console.error(error.message);
    console.error(error.stack);
};

/**
 * Logger for warnings.
 *
 * @function  logError
 * @param     {String}  msg  The message to log.
 */
const logWarn = (msg) => {
    console.warn(`[HARC] ${msg}`);
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

/**----------------------------------------------------------------
 * DNS-over-HTTP utility functions.
 *----------------------------------------------------------------*/

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
        if (payload.choice === "disable") {
            VALIDATION_RESULT_MAP.clear();
            browser.browserAction.setBadgeText({ text: "-" });
            browser.browserAction.setBadgeBackgroundColor({
                color: [211, 211, 211, 255],
            });
            logDebug("HARC validation disabled.");
        }

        DNS_DOH_RESOLVER = DOH_SERVER_CHOICES.get(payload.choice);
        logDebug(`Saved DOH server preference: ${payload.choice}`);
    } else {
        DNS_DOH_RESOLVER = DOH_SERVER_CHOICES.get("cloudflare-mozilla");
        result.success = false;
        result.message = "Unrecognised option selected.";
    }

    if (
        DNS_DOH_RESOLVER !== null &&
        (await browser.browserAction.getBadgeText({})) !== "!"
    ) {
        browser.browserAction.setBadgeText({ text: "" });
    }

    return result;
};

/**----------------------------------------------------------------
 * HARC Main Logic.
 *----------------------------------------------------------------*/

/**
 * A listener to capture the incoming response body content.
 * See: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/filterResponseData
 *
 * @function  captureResponseContent
 * @param     {object}  request  The request object.
 */
const captureResponseContent = async (request) => {
    const { requestId, tabId, url } = request;

    if (!TAB_RESPONSES_MAP.has(tabId)) {
        TAB_RESPONSES_MAP.set(tabId, new Map());
    }

    // Get the tab object to access main resource's URL.
    const tab = await browser.tabs.get(tabId);

    if (url === tab.url) {
        VALIDATION_RESULT_MAP.delete(tabId);
    }

    let decoder;
    const responseChunksArrayBuffer = [];
    const responseChunks = [];
    const responseFilter = browser.webRequest.filterResponseData(requestId);

    responseFilter.onstart = () => {
        // This will occur after the response headers have been received.
        if (TAB_RESPONSES_ENCODING_MAP.has(requestId)) {
            decoder = new TextDecoder(
                TAB_RESPONSES_ENCODING_MAP.get(requestId),
            );
            TAB_RESPONSES_ENCODING_MAP.delete(requestId);
        } else {
            // Default to latin1 encoding.
            decoder = new TextDecoder("latin1");
        }
    };

    responseFilter.ondata = (event) => {
        responseFilter.write(event.data);

        // event.data is an ArrayBuffer.
        responseChunksArrayBuffer.push(event.data);

        const chunk = decoder.decode(event.data, { stream: true });
        responseChunks.push(chunk);
    };

    responseFilter.onstop = async () => {
        responseFilter.close();
        responseChunks.push(decoder.decode());

        const responseBlob = new Blob(responseChunksArrayBuffer);

        const responseData = {
            ab: str2ab(responseChunks.join("")),
            blob: await responseBlob.arrayBuffer(),
        };

        const tabResponses = TAB_RESPONSES_MAP.get(tabId);
        tabResponses.set(request.url, responseData);
    };
};

/**
 * A listener to capture the incoming response header and set
 * the response content encoding. This is needed to determine
 * the correct encoding to use when decoding the response content.
 *
 * @function  captureResponseEncoding
 * @param     {object}  response  The response object.
 */
const captureResponseEncoding = (response) => {
    const { requestId } = response;

    // Default to latin1.
    TAB_RESPONSES_ENCODING_MAP.set(requestId, "latin1");

    // eslint-disable-next-line no-restricted-syntax
    for (const header of response.responseHeaders) {
        if (header.name.toLowerCase() === "content-type") {
            if (
                header.value.startsWith("text/html") ||
                header.value.includes("charset=utf-8") ||
                header.value.includes("charset=utf8")
            ) {
                TAB_RESPONSES_ENCODING_MAP.set(requestId, "utf-8");
            }
            break;
        }
    }
};

/**
 * A listener to clear records pertaining to a closed tab.
 *
 * @function  clearTabRecords
 * @param     {int}     tabId       The ID of the closed tab.
 */
const clearTabRecords = (tabId) => {
    if (TAB_ACTION_MAP.has(tabId)) {
        TAB_ACTION_MAP.delete(tabId);
    }
    if (TAB_RESPONSES_MAP.has(tabId)) {
        TAB_RESPONSES_MAP.delete(tabId);
    }
    if (VALIDATION_RESULT_MAP.has(tabId)) {
        VALIDATION_RESULT_MAP.delete(tabId);
    }
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
        console.error(
            `[HARC] Failed to resolve '${DNS_DOH_RESOLVER}'. Unable to proceed.`,
        );
        return ["doh-failure", null];
    }

    // eslint-disable-next-line no-undef
    const resolver = new doh.DohResolver(DNS_DOH_RESOLVER);
    logDebug(`Querying DOH Server: ${DNS_DOH_RESOLVER}`);
    logDebug(`Querying TXT Record: ${dnsQueryDomain}`);

    let action = "warn";
    let publicKeyDer = null;

    try {
        const dnsResponse = await resolver.query(dnsQueryDomain, "TXT");

        if (dnsResponse.answers.length === 0) {
            // No such DNS record.
            return [null, null];
        }

        const payload = dnsResponse.answers[0].data.toString().split(";");

        if (payload.length === 1) {
            // Assume only public key in DNS record. Default to "warn" action.
            publicKeyDer = payload[0].trim();
        } else if (payload.length === 2) {
            // [action, publicKey]
            action = payload[0].trim().toLowerCase();
            publicKeyDer = payload[1].trim();

            if (!HARC_VALID_ACTIONS.includes(action)) {
                // Invalid DNS record. Assume HARC not enabled.
                return [null, null];
            }
        } else {
            // Invalid DNS record. Assume HARC not enabled.
            return [null, null];
        }
    } catch (error) {
        logError(error);
        return ["doh-failure", null];
    }

    return [action, publicKeyDer];
};

/**
 * Handle onMessage event.
 *
 * @async
 * @function  handleOnMessage
 * @param     {object}  message  The message object.
 */
const handleOnMessage = async (message) => {
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
            break;
    }

    return result;
};

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

        browser.tabs.executeScript(tabId, {
            file: failureAction,
        });
    }
};

/**
 * Validate the response content.
 *
 * @async
 * @function  verifyResponseContent
 * @param     {object}  response  The response object.
 */
const verifyResponseContent = async (response) => {
    if (response.url === DNS_DOH_RESOLVER) {
        // Ignore if response is from DOH server.
        return;
    }

    // Get the tab ID of the response.
    const { tabId } = response;

    if (DNS_DOH_RESOLVER === null) {
        // HARC validation disabled by user.
        return;
    }

    // Get all the response data for the active tab.
    const tabResponses = TAB_RESPONSES_MAP.get(tabId);

    if (!tabResponses.has(response.url)) {
        // Request probably not part of filter.
        return;
    }

    // Get the tab object to access main resource's URL.
    const tab = await browser.tabs.get(tabId);

    const dnsPayload = await getHARCDNSPayload(new URL(response.url));
    let action = dnsPayload[0];
    const publicKeyDer = dnsPayload[1];

    if (action === null && publicKeyDer === null) {
        // HARC is not enabled on this domain.
        logDebug(`HARC not enabled on: ${response.url}`);

        if (VALIDATION_RESULT_MAP.has(tabId)) {
            const currentResult = VALIDATION_RESULT_MAP.get(tabId);

            if (currentResult === null) {
                VALIDATION_RESULT_MAP.set(tabId, "ignored-domain");
            } else if (currentResult === "trusted") {
                VALIDATION_RESULT_MAP.set(tabId, "trusted-partial");
            }
        } else {
            VALIDATION_RESULT_MAP.set(tabId, "ignored-domain");
        }

        browser.browserAction.setBadgeText({ tabId: tabId, text: "" });
        return;
    }

    if (response.url === tab.url) {
        // Set the action to take on failure based on main resource's defined action.
        TAB_ACTION_MAP.set(tabId, action);
    } else {
        // Use the main resource's action instead.
        // Wait up to 10 seconds for main resource's action to be retrieved.
        for (let i = 0; i < 10; ++i) {
            if (TAB_ACTION_MAP.has(tabId)) {
                break;
            }
            // Sleep for 1 second.
            // eslint-disable-next-line no-await-in-loop
            await new Promise((c) => {
                setTimeout(c, 1000);
            });
        }

        if (tabResponses.has(response.url)) {
            action = TAB_ACTION_MAP.get(tabId);
        } else {
            // Fallback to current resource's defined action instead.
            logWarn(
                "Failed to retrieve main resource's action. Using current resource's action.",
            );
        }
    }

    let publicKey = null;
    let signature = null;
    let signatureEncoded = null;

    response.responseHeaders.forEach((header) => {
        switch (header.name.toLowerCase()) {
            case HARC_HEADER_ALGO:
                logDebug(`Algorithm: ${header.value.trim()}`);
                break;
            case HARC_HEADER_DIGEST:
                logDebug(`Digest: ${header.value.trim()}`);
                break;
            case HARC_HEADER_SIGNATURE:
                signatureEncoded = header.value.trim();
                logDebug(`Signature: ${signatureEncoded}`);
                break;
            default:
                // Do nothing.
                break;
        }
    });

    // Attempt to parse the public key obtained from DNS.
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
        logDebug(`publicKeyDer: ${publicKeyDer}`);
        logError(error);
    }

    if (publicKey === null) {
        // Failed to parse public key.
        logWarn(
            "Failed to parse public key. Cannot proceed with response content validation.",
        );
        invokeFailure(tabId, action);
        return;
    }

    if (signatureEncoded === null) {
        // HARC enabled but did not receive signature header.
        logWarn(`Missing header: ${HARC_HEADER_SIGNATURE}`);
        invokeFailure(tabId, action);
        return;
    }

    try {
        signature = str2ab(window.atob(signatureEncoded));
    } catch (error) {
        // Failed to decode the signature.
        logError(error);
        invokeFailure(tabId, action);
        return;
    }

    const responseData = tabResponses.get(response.url);

    // Verify using the data obtained from blob.
    // This is used as certain binary payloads (e.g. images) do not work with str2ab.
    // Some resources doesn't play nicely with blob, and will fallback to str2ab.
    let signatureVerified = await crypto.subtle.verify(
        {
            name: EC_TYPE,
            hash: DIGEST_ALGO,
        },
        publicKey,
        signature,
        responseData.blob,
    );

    if (!signatureVerified) {
        // Try using the data generated using str2ab.
        signatureVerified = await crypto.subtle.verify(
            {
                name: EC_TYPE,
                hash: DIGEST_ALGO,
            },
            publicKey,
            signature,
            responseData.ab,
        );
    }

    // Data stored in 'tabResponses' no longer needed.
    tabResponses.delete(response.url);

    if (signatureVerified) {
        logDebug(`Signature verified: ${response.url}`);
        browser.browserAction.setBadgeText({ tabId: tabId, text: "" });

        if (VALIDATION_RESULT_MAP.has(tabId)) {
            const currentResult = VALIDATION_RESULT_MAP.get(tabId);

            if (currentResult === "ignored-domain") {
                VALIDATION_RESULT_MAP.set(tabId, "trusted-partial");
            } else if (
                !["doh-failure", "trusted-partial", "untrusted"].includes(
                    currentResult,
                )
            ) {
                VALIDATION_RESULT_MAP.set(tabId, "trusted");
            }
        } else {
            VALIDATION_RESULT_MAP.set(tabId, "trusted");
        }
    } else {
        console.error(
            `[HARC] Signature validation failed for resource: ${response.url}`,
        );
        invokeFailure(tabId, action);
    }
};

/**
 * Extension entrypoint.
 *
 * @function  entrypoint
 */
const entrypoint = async () => {
    VALIDATION_RESULT_MAP.clear();

    browser.runtime.onMessage.addListener(handleOnMessage);

    browser.tabs.onRemoved.addListener(clearTabRecords);

    browser.webRequest.onBeforeRequest.addListener(
        captureResponseContent,
        {
            types: ["font", "image", "imageset", "main_frame"],
            urls: ["http://*/*", "https://*/*"],
        },
        ["blocking"],
    );

    browser.webRequest.onHeadersReceived.addListener(
        captureResponseEncoding,
        {
            types: ["font", "image", "imageset", "main_frame"],
            urls: ["http://*/*", "https://*/*"],
        },
        ["blocking", "responseHeaders"],
    );

    browser.webRequest.onCompleted.addListener(
        verifyResponseContent,
        {
            types: ["font", "image", "imageset", "main_frame"],
            urls: ["http://*/*", "https://*/*"],
        },
        ["responseHeaders"],
    );
};

entrypoint();

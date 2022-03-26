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

// DEVELOPMENT USE ONLY.
const DEBUG = false;

const DNS_DOH_RESOLVER = "https://1.1.1.1/dns-query";
const EC_CURVE = "P-256";
const EC_TYPE = "ECDSA";
const HARC_DNS_PREFIX = "._arc.";
const HARC_HEADER_DIGEST = "x-arc-digest";
const HARC_HEADER_SIGNATURE = "x-arc-signature";
const HASH_ALGO = "SHA-256";
const RESPONSE_MAP = new Map();

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
 * Invoke the failure action.
 *
 * @function  invokeFailure
 */
const invokeFailure = (action) => {
    let failureAction = "src/warn.js";

    if (action === "enforce") {
        failureAction = "src/block.js";
    }

    // eslint-disable-next-line no-undef
    browser.tabs.executeScript({
        file: failureAction,
    });
};

/**
 * A listener to capture the incoming response body content.
 * See: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/filterResponseData
 *
 * @function  captureResponseContent
 * @param     {details}  request  The request details.
 */
const captureResponseContent = (request) => {
    const responseFilter = browser.webRequest.filterResponseData(
        request.requestId,
    );
    const content = [];
    const decoder = new TextDecoder("utf-8");
    const encoder = new TextEncoder("utf-8");

    responseFilter.ondata = (event) => {
        const data = decoder.decode(event.data, { stream: true });
        content.push(data);
        responseFilter.write(encoder.encode(data));
    };

    // eslint-disable-next-line no-unused-vars
    responseFilter.onstop = (event) => {
        responseFilter.close();
        RESPONSE_MAP.set(request.url, str2ab(content.join("")));
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
    const dnsQueryDomain = `${domain.subdomain}${HARC_DNS_PREFIX}${domain.domain}`;

    // eslint-disable-next-line no-undef
    const resolver = new doh.DohResolver(DNS_DOH_RESOLVER);
    logDebug(`Querying: ${dnsQueryDomain}`);

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
        return [null, null];
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

            let publicKey;
            let signature = "";

            const dnsPayload = await getHARCDNSPayload(new URL(response.url));
            const action = dnsPayload[0];
            const publicKeyDer = dnsPayload[1];

            response.responseHeaders.forEach((header) => {
                switch (header.name) {
                    case HARC_HEADER_DIGEST:
                        logDebug(`Digest: ${header.value.trim()}`);
                        break;
                    case HARC_HEADER_SIGNATURE:
                        signature = str2ab(window.atob(header.value.trim()));
                        break;
                    default:
                    // Do nothing.
                }
            });

            if (signature.length === 0) {
                if (
                    (action === null || action !== "enforce") &&
                    publicKeyDer === null
                ) {
                    // HARC is not enabled on this domain.
                    logDebug("HARC not enabled on this domain.");
                    return;
                }

                console.warn(`[HARC] Missing header: ${HARC_HEADER_SIGNATURE}`);
                invokeFailure(action);
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
                invokeFailure(action);
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
                invokeFailure(action);
                return;
            }

            const responseContent = RESPONSE_MAP.get(response.url);
            RESPONSE_MAP.delete(response.url);

            const signatureVerified = await crypto.subtle.verify(
                {
                    name: EC_TYPE,
                    hash: HASH_ALGO,
                },
                publicKey,
                signature,
                responseContent,
            );

            if (!signatureVerified) {
                console.error("[HARC] Signature validation failed!");
                invokeFailure(action);
            } else {
                logDebug("Signature verified.");
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
const entrypoint = () => {
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

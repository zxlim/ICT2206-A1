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

const DIGEST_ALGO = "SHA-256";
const DNS_DOH_RESOLVER = "https://1.1.1.1/dns-query";
const EC_CURVE = "P-256";
const EC_TYPE = "ECDSA";
const HARC_DNS_SUBDOMAIN = "_arc";
const HARC_HEADER_DIGEST = "x-arc-digest";
const HARC_HEADER_SIGNATURE = "x-arc-signature";
const RESPONSE_MAP = new Map();

// Text-like content with application prefix.
const APP_CONTENT_TYPE_TO_VERIFY = [
    "application/javascript",
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/atom+xml",
];

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

            let contentType = "";
            let publicKey = null;
            let signature = null;

            response.responseHeaders.forEach((header) => {
                switch (header.name.toLowerCase()) {
                    case HARC_HEADER_DIGEST:
                        logDebug(`Digest: ${header.value.trim()}`);
                        break;
                    case HARC_HEADER_SIGNATURE:
                        try {
                            signature = str2ab(window.atob(header.value.trim()));
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

            if (
                !contentType.startsWith("text/") &&
                !APP_CONTENT_TYPE_TO_VERIFY.includes(contentType)
            ) {
                // Unsupported content type. Skip verification.
                logDebug(
                    `Skipping verification for '${response.url}': Unsupported content type '${contentType}'`,
                );
                return;
            }

            const dnsPayload = await getHARCDNSPayload(new URL(response.url));
            const action = dnsPayload[0];
            const publicKeyDer = dnsPayload[1];

            if (signature === null) {
                if (action === null && publicKeyDer === null) {
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

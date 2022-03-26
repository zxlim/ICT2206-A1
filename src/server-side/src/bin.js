#!/usr/bin/env node
/**
 * HTTP Authenticated Response Content (HARC):
 * Provides an additional layer of authentication through a Content Delivery Network.
 *
 * HARC Server-side signing server component.
 *
 * @author     Daniel Tan Zhonghao  <2001240@sit.singaporetech.edu.sg>
 * @author     Ho Xiu Qi            <1802962@sit.singaporetech.edu.sg>
 * @author     Lim Zhao Xiang       <1802976@sit.singaporetech.edu.sg>
 * @copyright  Copyright (c) 2022. For the fulfillment of the SIT module
 *             ICT2206 Web Security (AY2021/2022, Trimester 2).
 */
/* eslint-disable no-console */

const fs = require("fs");
const httpProxy = require("http-proxy");
const strftime = require("strftime");
const supportsColour = require("color-support");
const yargs = require("yargs/yargs");
const zlib = require("zlib");
const { hideBin } = require("yargs/helpers");
const { subtle } = require("crypto").webcrypto;

const CRYPTO_OUTPUT_ENCODING = "base64";
const DIGEST_ALGO = "SHA-256";
const EC_CURVE = "P-256";
const EC_TYPE = "ECDSA";
const HARC_HEADER_ALGO = "X-ARC-ALGO";
const HARC_HEADER_DIGEST = "X-ARC-DIGEST";
const HARC_HEADER_SIGNATURE = "X-ARC-SIGNATURE";

// Text-like content with application prefix.
const APP_CONTENT_TYPE_TO_SIGN = [
    "application/javascript",
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/atom+xml",
];

/**
 * Pretty console logger.
 *
 * @function  prettyLog
 * @param     {String}  msg    The string to to log to console.
 * @param     {String}  level  The log level. Accepts: ["verbose", "info", "warn", "error"]
 */
const prettyLog = (msg, level = "info") => {
    const ts = strftime("%Y-%m-%d %H:%M:%S");

    if (supportsColour()) {
        switch (level) {
            case "warn":
                console.warn(`[\x1b[33m${ts}\x1b[0m] ${msg}`);
                break;
            case "error":
                console.error(`[\x1b[31m${ts}\x1b[0m] ${msg}`);
                break;
            case "verbose":
                console.debug(`[\x1b[32m${ts}\x1b[0m] ${msg}`);
                break;
            default:
                console.info(`[\x1b[36m${ts}\x1b[0m] ${msg}`);
        }
    } else {
        switch (level) {
            case "warn":
                console.warn(`[${ts}] ${msg}`);
                break;
            case "error":
                console.error(`[${ts}] ${msg}`);
                break;
            case "verbose":
                console.debug(`[${ts}] ${msg}`);
                break;
            default:
                console.info(`[${ts}] ${msg}`);
        }
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

    for (let i = 0; i < str.length; i++) {
        buffer[i] = str.charCodeAt(i);
    }

    return buffer;
};

/**
 * Adaptation of window.atob for use in Node.js.
 * Decodes Base64 into an ISO-8859-1 encoded string.
 * Based on https://github.com/jsdom/abab
 *
 * @function  atob
 * @param     {String}  b64String  The Base64 string.
 * @returns   {String}             The decoded string.
 */
/* eslint-disable no-bitwise, no-multi-assign, no-param-reassign */
const atob = (b64String) => {
    const BASE64_CHAR_MAP =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    b64String = `${b64String}`;
    b64String = b64String.replace(/\s+/g, "").trim();

    if (b64String.length % 4 === 0) {
        b64String = b64String.replace(/==?$/, "");
    }

    if (b64String.length % 4 === 1 || /[^+/0-9A-Za-z]/.test(b64String)) {
        throw new TypeError(
            "Failed to execute 'atob': The string to be decoded is not correctly encoded.",
        );
    }

    let output = "";
    let accumulatedBits = 0;
    let buffer = 0;
    let index = 0;

    for (let i = 0; i < b64String.length; i++) {
        buffer <<= 6;

        index = BASE64_CHAR_MAP.indexOf(b64String[i]);

        if (buffer === -1) {
            throw new TypeError(
                "Failed to execute 'atob': The string to be decoded is not correctly encoded.",
            );
        }

        buffer |= index;
        accumulatedBits += 6;

        if (accumulatedBits === 24) {
            output += String.fromCharCode((buffer & 0xff0000) >> 16);
            output += String.fromCharCode((buffer & 0xff00) >> 8);
            output += String.fromCharCode(buffer & 0xff);
            buffer = accumulatedBits = 0;
        }
    }

    if (accumulatedBits === 12) {
        buffer >>= 4;
        output += String.fromCharCode(buffer);
    } else if (accumulatedBits === 18) {
        buffer >>= 2;
        output += String.fromCharCode((buffer & 0xff00) >> 8);
        output += String.fromCharCode(buffer & 0xff);
    }

    return output;
};
/* eslint-enable no-bitwise, no-multi-assign, no-param-reassign */

/**
 * Imports a ECDSA P-256 private key for use in JavaScript digital signature cryptography.
 *
 * @function  importSigningKey
 * @param     {String}  keyFilePath  The file path to the private key to import.
 * @returns   {Promise}              The Promise object for the importKey operation.
 */
const importSigningKey = (keyFilePath) => {
    const PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    const PEM_FOOTER = "-----END PRIVATE KEY-----";

    const pem = fs
        .readFileSync(keyFilePath)
        .toString()
        .replace(PEM_HEADER, "")
        .replace(PEM_FOOTER, "")
        .trim();
    const binaryDer = str2ab(atob(pem));

    return subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: EC_TYPE,
            namedCurve: EC_CURVE,
        },
        false,
        ["sign"],
    );
};

/**
 * HARC signing server logic.
 *
 * @function  serve
 * @param     {CryptoKey}  harcSigningKey  The HARC signing key.
 * @param     {Object}     args            Command line arguments.
 */
const serve = (harcSigningKey, args) => {
    const proxyServer = httpProxy.createProxyServer({
        selfHandleResponse: true,
        target: args.upstream,
        xfwd: !args.noXFwdFor,
    });

    // HTTP Response Event Listener.
    proxyServer.on("proxyRes", (proxyRes, request, response) => {
        /**
         * Common Log Format (CLF) HTTP request logger.
         *
         * @param {int}    contentLength  Response content length.
         * @param {String} digest         Response content digest.
         * @param {String} signature      Response content signature.
         */
        const commonLogFormat = (
            contentLength,
            digest = null,
            signature = null,
        ) => {
            let extra = "";
            let { statusCode } = proxyRes;
            let ts = strftime("%d/%b/%Y:%H:%M:%S %z");

            // Use X-Forwarded-For if present in request header.
            let client = request.headers["x-forwarded-for"]
                ? request.headers["x-forwarded-for"].split(",")[0].trim()
                : request.socket.remoteAddress;

            if (args.verbose && signature !== null) {
                const digestAlgo = DIGEST_ALGO.replace("-", "");
                const sigAlgo = `${EC_TYPE}_${digestAlgo}`;

                let digestLog = "";

                if (digest !== null) {
                    digestLog = supportsColour()
                        ? `${digestAlgo}:\x1b[32m${digest}\x1b[0m`
                        : `${digestAlgo}:${digest}`;
                }

                extra = supportsColour()
                    ? `${digestLog} ${sigAlgo}:\x1b[32m${signature}\x1b[0m`.trim()
                    : `${digestLog} ${sigAlgo}:${signature}`.trim();
            }

            if (supportsColour()) {
                client = `\x1b[35m${client}\x1b[0m`;
                ts = `\x1b[36m${ts}\x1b[0m`;

                if (proxyRes.statusCode >= 200 && proxyRes.statusCode <= 299) {
                    statusCode = `\x1b[32m${proxyRes.statusCode}\x1b[0m`;
                } else if (
                    proxyRes.statusCode >= 400 &&
                    proxyRes.statusCode <= 599
                ) {
                    statusCode = `\x1b[31m${proxyRes.statusCode}\x1b[0m`;
                }
            }

            // Log the request to console usng the common log format.
            console.info(
                `${client} - - [${ts}] "${request.method} ${request.url} HTTP/${
                    request.httpVersion
                }" ${statusCode} ${contentLength} "${
                    proxyRes.headers.referrer ?? "-"
                }" "${request.headers["user-agent"]}" ${extra}`.trim(),
            );
        };

        // Temporary buffer for incoming response content.
        const responseContent = [];

        // Ensure correct HTTP reponse status is set.
        response.statusCode = proxyRes.statusCode;
        response.statusMessage = proxyRes.statusMessage;

        // Add incoming data chunks to temporary buffer.
        proxyRes.on("data", (chunk) => {
            responseContent.push(chunk);
        });

        // Last data chunk received.
        proxyRes.on("end", async () => {
            let content;
            let encoding = "binary";

            const contentType = (
                proxyRes.headers["content-type"] ?? "-"
            ).toLowerCase();
            const contentEncoding = (
                proxyRes.headers["content-encoding"] ?? "-"
            ).toLowerCase();

            if (contentType.includes("charset=utf-8")) {
                // Only use UTF-8 if charset is specified.
                encoding = "utf-8";
            }

            if (contentEncoding.toLowerCase() === "gzip") {
                content = zlib
                    .gunzipSync(Buffer.concat(responseContent))
                    .toString(encoding);
            } else {
                content = Buffer.concat(responseContent).toString(encoding);
            }

            // Hack to clear array, don't want memory to pile up. CONTROVERSIAL.
            // See: https://stackoverflow.com/a/1232046
            responseContent.length = 0;
            // responseContent.splice(0, responseContent.length);

            Object.keys(proxyRes.headers).forEach((k) => {
                // Content already decompressed. No need to set encoding header.
                if (k.toLowerCase() !== "content-encoding") {
                    response.setHeader(k, proxyRes.headers[k]);
                }
            });

            if (response.hasHeader("content-length")) {
                // If mismatch, use the content length that HARC calculated instead.
                if (
                    parseInt(response.getHeader("content-length"), 10) !==
                    content.length
                ) {
                    // response.removeHeader("content-length");
                    // response.setHeader("transfer-encoding", "chunked");
                    response.setHeader("content-length", content.length);
                }
            }

            let digest = null;
            let signature = null;

            // Perform signing on "text-based" content only.
            if (
                contentType.includes("text/") ||
                APP_CONTENT_TYPE_TO_SIGN.includes(contentType)
            ) {
                // Useful if support for multiple algorithms is needed.
                // Format: SIGNATURE_ALGORITHM; DIGEST_ALGORITHM
                response.setHeader(
                    HARC_HEADER_ALGO,
                    `${EC_TYPE}_${EC_CURVE}; ${DIGEST_ALGO}`,
                );

                if (args.digestHeader) {
                    // Useful for development/troubleshooting.
                    digest = Buffer.from(
                        await subtle.digest(DIGEST_ALGO, str2ab(content)),
                    ).toString(CRYPTO_OUTPUT_ENCODING);

                    response.setHeader(HARC_HEADER_DIGEST, digest);
                }

                // Generate digital signature of response content.
                signature = Buffer.from(
                    await subtle.sign(
                        {
                            name: EC_TYPE,
                            hash: DIGEST_ALGO,
                        },
                        harcSigningKey,
                        str2ab(content),
                    ),
                ).toString(CRYPTO_OUTPUT_ENCODING);

                response.setHeader(HARC_HEADER_SIGNATURE, signature);
            }

            // Log the HTTP request to console and send response to client.
            commonLogFormat(content.length, digest, signature);
            response.end(content, encoding);
        });
    });

    // Signal handler for graceful exit.
    ["SIGINT", "SIGTERM"].forEach((signal) => {
        process.on(signal, () => {
            console.log("");
            prettyLog("Stopping server...", "warn");
            proxyServer.close();
            process.exit(0);
        });
    });

    proxyServer.listen(args.port, args.bind);
};

/**
 * Application entrypoint.
 *
 * @function  main
 */
const main = () => {
    // Command-line arguments. Use '-h' or '--help' to display help menu.
    const args = yargs(hideBin(process.argv))
        .usage("HTTP Authenticated Response Content (HARC) Signing Server.")
        .option("upstream", {
            alias: "u",
            type: "string",
            description: "Upstream server to proxy.",
            demandOption: true,
        })
        .option("signingKey", {
            alias: "k",
            type: "string",
            description: "Path to HARC signing key.",
            demandOption: true,
        })
        .option("bind", {
            alias: "b",
            type: "string",
            description: "Local address to bind to.",
            default: "0.0.0.0",
        })
        .option("port", {
            alias: "p",
            type: "integer",
            description: "TCP port to listen on.",
            default: 5000,
        })
        .option("digestHeader", {
            boolean: true,
            description: `Enable the ${HARC_HEADER_DIGEST} HTTP header.`,
        })
        .option("noXFwdFor", {
            boolean: true,
            description: "Disable the X-FORWARDED-FOR HTTP header.",
        })
        .option("verbose", {
            alias: "v",
            boolean: true,
            description: "Enable verbose logging.",
        })
        .example([
            [
                "$0 -u http://192.168.0.10 -k /etc/ssl/private/harc_signing_key.pem",
                "Proxy and sign responses for web application at http://192.168.0.10 with the private key specified using '-k'.",
            ],
            [
                "$0 -u http://127.0.0.1:8080 -k private.pem",
                "Proxy and sign responses for web application at http://127.0.0.1:8080 with the private key 'private.pem' located in the current directory.",
            ],
        ])
        .help()
        .alias("h", "help").argv;

    if (args.port < 1 || args.port > 65535) {
        prettyLog(
            `Failed to bind to port '${args.port}': Invalid port number`,
            "error",
        );
        process.exit(1);
    }

    // Ensure specified signing key exists and is accessible on the filesystem.
    const keyFileStat = fs.statSync(args.signingKey, { throwIfNoEntry: false });

    if (keyFileStat === undefined) {
        prettyLog(
            `Failed to load signing key '${args.signingKey}': No such file`,
            "error",
        );
        process.exit(1);
    } else if (!keyFileStat.isFile()) {
        prettyLog(
            `Failed to load signing key '${args.signingKey}': Not a file`,
            "error",
        );
        process.exit(1);
    }

    try {
        importSigningKey(args.signingKey)
            .then((harcSigningKey) => {
                if (args.verbose) {
                    prettyLog("Enabled verbose logging.", "verbose");
                }
                if (args.digestHeader) {
                    prettyLog(
                        `Enabled ${HARC_HEADER_DIGEST} HTTP header.`,
                        "verbose",
                    );
                }
                if (args.noXFwdFor) {
                    prettyLog("Disabled X-FORWARDED-FOR HTTP header.", "warn");
                }

                prettyLog(`Upstream Server: ${args.upstream}`);
                prettyLog(`HARC Signing Key: ${args.signingKey}`);
                prettyLog(
                    `HARC signing server listening on: ${args.bind}:${args.port}/tcp`,
                );

                try {
                    serve(harcSigningKey, args);
                } catch (error) {
                    prettyLog(
                        "HARC Signing Server has encountered an error.",
                        "error",
                    );
                    prettyLog(error.stack, "error");
                    process.exit(1);
                }
            })
            .catch((error) => {
                prettyLog(
                    `Failed to load signing key '${args.signingKey}'`,
                    "error",
                );
                prettyLog(error.stack, "error");
                process.exit(1);
            });
    } catch (error) {
        prettyLog(`Failed to load signing key '${args.signingKey}'`, "error");
        prettyLog(error.stack, "error");
        process.exit(1);
    }
};

main();

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
const log = require("fancy-log");
const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const { subtle } = require("crypto").webcrypto;

const EC_TYPE = "ECDSA";
const EC_CURVE = "P-256";
const HASH_ALGO = "SHA-256";

/**
 * Converts a String into a JavaScript ArrayBuffer object.
 *
 * @function  str2ab
 * @param     {String}  str  The string to convert.
 * @returns   {ArrayBuffer}  The ArrayBuffer instance.
 */
const str2ab = (str) => {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);

    for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i);
    }

    return buf;
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
 * @async
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
        xfwd: args.xfwd,
    });

    proxyServer.on("proxyReq", (proxyReq) => {
        // Don't deal with gzip compression.
        proxyReq.setHeader("Accept-Encoding", "*;q=1,gzip=0");
    });

    proxyServer.on("proxyRes", (proxyRes, request, response) => {
        const responseContent = [];

        log.info(
            `"${request.method} ${request.url} HTTP/${request.httpVersion}" ${proxyRes.statusCode} "${request.headers["user-agent"]}"`,
        );

        proxyRes.on("data", (chunk) => {
            responseContent.push(chunk);
        });

        // Last data chunk received.
        proxyRes.on("end", async () => {
            const content = Buffer.concat(responseContent).toString();

            Object.keys(proxyRes.headers).forEach((k) => {
                response.setHeader(k, proxyRes.headers[k]);
            });

            const contentType = response.getHeader("content-type") ?? "unknown";

            // Perform signing on HTML content only.
            if (contentType.includes("text/html")) {
                // Generate digital signature using ECDSA-SHA256 algorithm in base64 encoding.
                const signature = Buffer.from(
                    await subtle.sign(
                        {
                            name: EC_TYPE,
                            hash: HASH_ALGO,
                        },
                        harcSigningKey,
                        str2ab(content),
                    ),
                ).toString("base64");

                // Set the signature in the response header.
                response.setHeader("X-ARC-SIGNATURE", signature);

                if (args.verbose) {
                    log.info(`Signature: ${signature}`);
                }
            }

            response.end(content);
        });
    });

    log.info(`HARC signing server listening on: ${args.port}/tcp`);
    proxyServer.listen(args.port);
};

const main = () => {
    const args = yargs(hideBin(process.argv))
        .usage("HTTP Authenticated Response Content (HARC) Signing Server.")
        .option("port", {
            alias: "p",
            type: "integer",
            description: "TCP port to listen on.",
            default: 5000,
        })
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
        .option("xfwd", {
            boolean: true,
            description: "Enable the X-FORWARDED-FOR HTTP header.",
        })
        .option("verbose", {
            alias: "v",
            boolean: true,
            description: "Enable verbose logging.",
        })
        .help()
        .alias("h", "help").argv;

    if (args.port < 1 || args.port > 65535) {
        console.error(
            `Failed to bind to port '${args.port}': Invalid port number`,
        );
        process.exit(1);
    }

    const keyFileStat = fs.statSync(args.signingKey, { throwIfNoEntry: false });

    if (keyFileStat === undefined) {
        console.error(
            `Failed to load signing key '${args.signingKey}': No such file`,
        );
        process.exit(1);
    } else if (!keyFileStat.isFile()) {
        console.error(
            `Failed to load signing key '${args.signingKey}': Not a file`,
        );
        process.exit(1);
    }

    importSigningKey(args.signingKey).then((harcSigningKey) => {
        if (args.verbose) {
            log.info(`Upstream Server: ${args.upstream}`);
            log.info(`HARC Signing Key: ${args.signingKey}`);

            if (args.xfwd) {
                log.info("Enabled X-FORWARDED-FOR HTTP header.");
            }
        }

        serve(harcSigningKey, args);
    });
};

main();

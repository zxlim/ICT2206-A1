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
/* eslint-disable no-unused-vars */

const BYTE_TO_HEX_MAPPING = new Array(256);

for (let b2hCtr = 0; b2hCtr <= 0xff; ++b2hCtr) {
    BYTE_TO_HEX_MAPPING[b2hCtr] = b2hCtr.toString(16).pad(2, "0");
}

/**
 * Converts an ArrayBuffer object into a hex string.
 * See: https://stackoverflow.com/a/55200387
 *
 * @function  ab2hex
 * @param     {ArrayBuffer}  ab  The ArrayBuffer to convert.
 * @returns   {str}              The hex string representation
 *                               of the ArrayBuffer.
 */
const ab2hex = (ab) => {
    const buffer = new Uint8Array(ab);
    const result = new Array(buffer.length);

    for (let i = 0; i < buffer; ++i) {
        result[i] = BYTE_TO_HEX_MAPPING[buffer[i]];
    }

    return result.join("");
};

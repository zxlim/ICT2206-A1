// Constants
const SIGNATURE_HEADER = "x-aehx-signature";
const SHA_HEADER = "x-aehx-sha256";
const DNS_RECORD_PREFIX = "._aehx.";
const MAX_KEY_REQ_TRIES = 5;
const MAX_RESP_WAIT_TRIES = 5;
const AWAIT_INTERVAL = 1000;
const ALGORITHM = ""


// Global var for holding retrieved public keys from DNS
var keys = new Map();
var resps = new Map();


// Kick-start PUB key retrieval
browser.webRequest.onBeforeRequest.addListener(
  getPubKey,
  {urls: ["<all_urls>"]}
);

// Add listener for getting response body
browser.webRequest.onBeforeRequest.addListener(
  responseCapture,
  {urls: ["<all_urls>"], types: ["main_frame"]},
  ["blocking"]
);

// Function to capture response data of HTTP request
function responseCapture(requestDetails) {
	let filter = browser.webRequest.filterResponseData(requestDetails.requestId);
  let decoder = new TextDecoder("utf-8");
  

  filter.ondata = event => {
    let str = decoder.decode(event.data, {stream: true});
    // Capture the response body into the map
    resps.set(requestDetails.url, str);

    // Forward response to browser
		filter.write(event.data);

		// Clean up filter
    filter.close();
  }
}


// Function to retrieve response headers & body upon completion
browser.webRequest.onCompleted.addListener(
  parseResponse,
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);


function parseDNSresponse(url, responseData) {
	// Get the key from the TXT record
	let key = responseData.split(';')[1].trim();
	console.log("Parsed Key from Response: "+key);
	// Set the key in 'keys' Map
	keys.set(url, key);
}

// Async function to retrieve public key from TXT field of DNS
async function getPubKey(requestDetails){

	// Setup doh resolver
	const resolver = new doh.DohResolver('https://1.1.1.1/dns-query');

	// Ignore all requests for the DohResolver
	if (requestDetails.url == "https://1.1.1.1/dns-query") {
		return {};
	}

	// Replace protocol string (http/https)
	let url = requestDetails.url.replace('http://','').replace('https://','').split('/')[0];

	// Call psl function to parse domain name
	var parsed = psl.parse(url);

	// Make the query url
	let query_url = parsed.subdomain + DNS_RECORD_PREFIX + parsed.domain;
	console.log("Querying: "+query_url);

	resolver.query(query_url, 'TXT')
	  .then(response => {
	    response.answers.forEach(ans => parseDNSresponse(requestDetails.url, ans.data.toString()));
	  })
	  .catch(err => console.error(err));

	// If DNS record has TXT field, parse the key into 'keys' Map
}


function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}


async function parseResponse(requestDetails) {

	let signature = "";

	requestDetails.responseHeaders.forEach(function (header) {
		if (header.name == SIGNATURE_HEADER) {
			signature = header.value;
		}
		else if (header.name == SHA_HEADER) {
			console.log("[SHA256]"+header.value);
		}
	});

	// If signature header not found, requested website doesnt support WAU protocol 
	// (or it can be just a normal web resource)
	if (signature == ""){
		console.log("[-] Signature field not found for url: "+requestDetails.url);
	}
	// Else if signature header found
	else {

		// Ensure public key has already been retrieved
		let ctr = 0;
		(async() => {
	    while(keys.get(requestDetails.url) == undefined) {
	    	if (ctr > MAX_KEY_REQ_TRIES) {
	    		break;
	    	}
	    	ctr = ctr + 1;
	    	await new Promise(resolve => setTimeout(resolve, AWAIT_INTERVAL));
	    }
	    
	    // If Pub Key request exceeded max tries, inform user that key could not be obtained
	    if (ctr > MAX_KEY_REQ_TRIES) {
	    	console.log("[-] Timeout: Failed to obtain Public Key: "+keys.get(requestDetails.url));
	    }
	    // Else, key was found and use it to decrypt signature field
	    else {

	    	let encoder = new TextEncoder("utf-8");

	    	// Encode key into ArrayBuffer
	    	let keyData = str2ab(window.atob(keys.get(requestDetails.url)));

	    	// Craft the 'EcKeyImportParams' algorithm object
	    	let ecKeyImportParams = {name:"ECDSA",namedCurve:"P-256"};
	    	// console.log(Object.keys(ecKeyImportParams));

    		// Import the key
    		let key = await crypto.subtle.importKey(
				    "spki",
				    keyData,
				    ecKeyImportParams,
				    false,
				    ["verify"]
				);

	    	// Ensure response data has been fully retrieved first
	    	let ctr2 = 0;
	    	(async() => {
			    while(resps.get(requestDetails.url) == undefined) {
			    	if (ctr2 > MAX_RESP_WAIT_TRIES) {
			    		break;
			    	}
			    	ctr2 = ctr2 + 1;
			    	await new Promise(resolve => setTimeout(resolve, AWAIT_INTERVAL));
			    }
	    		// If Pub Key request exceeded max tries, inform user that key could not be obtained
			    if (ctr2 > MAX_RESP_WAIT_TRIES) {
			    	console.log("[-] Timeout: Failed to obtain response data");
			    }
			    else {
			    	let data = resps.get(requestDetails.url);

	    			console.log("[SIGNATURE]"+signature);
						const digest = await crypto.subtle.digest("SHA-256", str2ab(data));

						console.log("[DIGEST]"+buf2hex(digest));
						

			    	// Verify response body's integrity
			    	const result = await crypto.subtle.verify({
												      name: "ECDSA",
												      hash: {name: "SHA-256"},
												    }, 
												    key, 
												    str2ab(window.atob(signature)),
												    str2ab(data));

						// Update results map
						console.log("[*] Verification Result: "+result);
			    }
	    	}) ();
	    }

		}) ();
	}
}

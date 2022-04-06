# HARC Proxy Server

This is the Node application for signing outgoing HTTP responses.

## Setup Instructions

This section covers the setup instructions for HARC Proxy Server.

### Dependencies

[Node](https://nodejs.org/en/) and the Node Package Manager (npm) is required to build the application from source. It can be installed using [Node Version Manager (nvm)](https://github.com/nvm-sh/nvm).

Additional Node packages are required to build and run the application from source. Use the command `npm install` to install the necessary packages.

### Building from source

Run the command `npm run build` to build the distributable binary package. The package will be available under the `dist/` directory.

Currently, this only builds the package for Linux based on Node 16. To build for other operating systems (e.g. macOS or Windows) or Node versions, modify the `build` script in `package.json`.

### Running from source

Run the command `node src/bin.js` to run the application from source.

## Usage Instructions

Run the application with the `--help` flag to see the available arguments and flags as well as usage examples.

```bash
HTTP Authenticated Response Content (HARC) Signing Server.

Options:
      --version       Show version number                              [boolean]
  -u, --upstream      Upstream server to proxy.              [string] [required]
  -k, --signingKey    Path to HARC signing key.              [string] [required]
  -b, --bind          Local address to bind to.    [string] [default: "0.0.0.0"]
  -p, --port          TCP port to listen on.                     [default: 5000]
      --digestHeader  Enable the X-ARC-DIGEST HTTP header.             [boolean]
      --noXFwdFor     Disable the X-FORWARDED-FOR HTTP header.         [boolean]
  -v, --verbose       Enable verbose logging.                          [boolean]
  -h, --help          Show help                                        [boolean]

Examples:
  harc-server -u http://192.168.0.10 -k     Proxy and sign responses for web
  /etc/ssl/private/harc_signing_key.pem     application at http://192.168.0.10
                                            with the private key specified using
                                            '-k'.
  harc-server -u http://127.0.0.1:8080 -k   Proxy and sign responses for web
  private.pem                               application at http://127.0.0.1:8080
                                            with the private key 'private.pem'
                                            located in the current directory.
```

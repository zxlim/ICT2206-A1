#!/usr/bin/env bash

if ! command -v openssl &> /dev/null; then
    echo "[-] OpenSSL is required for this script to work."
    exit 1
elif ! command -v sed &> /dev/null; then
    echo "[-] sed is required for this script to work."
    exit 1
fi

OUT_DIR="./private"
FILE_PRIVATE="${OUT_DIR}/private.key"
FILE_PRIVATE_PKCS8="${OUT_DIR}/harc.pem"
FILE_PUBLIC="${OUT_DIR}/public.key"
FILE_PUBLIC_DNS="${OUT_DIR}/dns_public_key.txt"

if [ -d "${OUT_DIR}" ]; then
    rm -f ${FILE_PRIVATE} ${FILE_PRIVATE_PKCS8} ${FILE_PUBLIC} ${FILE_PUBLIC_DNS}
else
    echo "[*] Creating directory: ${OUT_DIR}"
    mkdir -p ${OUT_DIR}
fi

# Generate ECDSA (P-256 curve) private key.
openssl ecparam -name prime256v1 -genkey -noout -out ${FILE_PRIVATE} && \
# Convert private key into PKCS8 format.
openssl pkcs8 -topk8 -nocrypt -in ${FILE_PRIVATE} -out ${FILE_PRIVATE_PKCS8} && \
chmod 600 ${FILE_PRIVATE} ${FILE_PRIVATE_PKCS8} && \
# Generate public key
openssl ec -in ${FILE_PRIVATE} -pubout -out ${FILE_PUBLIC} && \
# Output the public key in a format suitable for DNS TXT record.
sed "1d; \$d" ${FILE_PUBLIC} | tr -d "\n" > ${FILE_PUBLIC_DNS} && \
echo "" >> ${FILE_PUBLIC_DNS} && \
echo "[+] Generated HARC Signing Key: ${FILE_PRIVATE_PKCS8}" && \
echo "[+] Publish the contents of '${FILE_PUBLIC_DNS}' in your DNS."

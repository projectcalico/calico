#!/bin/bash
# filepath: /home/william/Repos/calico-oss/guardian/test/generate-certs.sh

set -e

# Define output directory
CERT_DIR="test/tmp"
mkdir -p "$CERT_DIR"

# Define file paths
ROOT_CA_CERT="$CERT_DIR/rootCA.crt"
ROOT_CA_KEY="$CERT_DIR/rootCA.key"
SERVER_CERT="$CERT_DIR/server.crt"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CSR="$CERT_DIR/server.csr"
CONFIG_FILE="$CERT_DIR/openssl.cnf"

# Generate OpenSSL configuration file
cat > "$CONFIG_FILE" <<EOF
[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[req_distinguished_name]
C  = US
ST = California
L  = San Francisco
O  = MockServer
OU = Testing
CN = 127.0.0.1

[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

# Step 1: Generate Root CA
echo "Generating Root CA private key..."
openssl genrsa -out "$ROOT_CA_KEY" 2048

echo "Generating Root CA certificate..."
openssl req -x509 -new -nodes -key "$ROOT_CA_KEY" -sha256 -days 3650 -out "$ROOT_CA_CERT" -subj "/C=US/ST=California/L=San Francisco/O=MockCA/OU=Testing/CN=MockRootCA"

# Step 2: Generate Server Private Key
echo "Generating server private key..."
openssl genrsa -out "$SERVER_KEY" 2048

# Step 3: Generate Server CSR (Certificate Signing Request)
echo "Generating server CSR..."
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$CONFIG_FILE"

# Step 4: Sign Server Certificate with Root CA
echo "Signing server certificate with Root CA..."
openssl x509 -req -in "$SERVER_CSR" -CA "$ROOT_CA_CERT" -CAkey "$ROOT_CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 365 -sha256 -extfile "$CONFIG_FILE" -extensions req_ext

# Output file paths
echo "Certificates and keys have been generated:"
echo "Root CA Certificate: $ROOT_CA_CERT"
echo "Root CA Private Key: $ROOT_CA_KEY"
echo "Server Certificate: $SERVER_CERT"
echo "Server Private Key: $SERVER_KEY"
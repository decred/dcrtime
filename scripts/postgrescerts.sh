#!/usr/bin/env bash
# This script creates the certificates required to run a PostgreSQL node
# locally. This includes creating a CA certificate, a node certificate, one 
# root client to connect via cli, and one more client certificate for dcrtimed
#
# NOTE: this scripts creates and copies over the server files (server.crt, 
# server.key & root.crt) to postgrees data dir, is uses $PGDATA environment
# variable to determine where to copy the files to, make sure it's exported
# before running the script.
# when done creating & moving certs this script restarts postgres server
# in order to load created server certs.
#
# More information on PostgreSQL ssl connection usage can be found at:
# https://www.postgresql.org/docs/9.5/ssl-tcp.html

set -ex

# Database usernames
readonly USER_DCRTIMED="dcrtimed"

# POSTGRES_DIR is where all of the certificates will be created.
POSTGRES_DIR=$1
if [ "${POSTGRES_DIR}" == "" ]; then
  POSTGRES_DIR="${HOME}/.postgresql"
fi

# Create postgresdb clients directories.
mkdir -p "${POSTGRES_DIR}/certs/clients/root"
mkdir -p "${POSTGRES_DIR}/certs/clients/${USER_DCRTIMED}"

# Create a CA private key
echo "Generating root.key, please type a password:"
openssl genrsa -des3 -out root.key 4096
# Remove passphrase
echo "Removing root.key password, please re-type it:"
openssl rsa -in root.key -out root.key -passout pass:123

# Create a root Certificate Authority (CA)
openssl \
    req -new -x509 \
    -days 365 \
    -subj "/CN=CA" \
    -key root.key \
    -out root.crt

# Create server key
echo "Generating server.key, please type a password:"
openssl genrsa -des3 -out server.key 4096 -passout pass:123
#Remove a passphrase
echo "Removing server.key password, please re-type it:"
openssl rsa -in server.key -out server.key -passout pass:123

# Create a root certificate signing request
openssl \
    req -new \
    -key server.key \
    -subj "/CN=localhost" \
    -text \
    -out server.csr

# Create server certificate
openssl \
    x509 -req \
    -in server.csr \
    -text \
    -days 365 \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -out server.crt

# Copy server.key, server.crt & root.crt to postgres' data dir as discribed in
# PostgresSQL ssl connection documentation, it uses environment variable PGDATA
# as postgres' data dir
echo "Copying server.key server.crt root.crt to $PGDATA as postgres sys user"
sudo -u postgres cp server.key server.crt root.crt $PGDATA

# Create root client key - used to connect via cli
openssl genrsa -out client.root.key 4096
# Remove passphrase
openssl rsa -in client.root.key -out client.root.key

chmod og-rwx client.root.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key client.root.key \
    -subj "/CN=postgres" \
    -out client.root.csr

# Create client certificate
openssl \
    x509 -req \
    -in client.root.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out client.root.crt

# Copy client to certs dir
cp client.root.key client.root.crt root.crt \
  ${POSTGRES_DIR}/certs/clients/root

# Create client key for dcrtimed
openssl genrsa -out client.${USER_DCRTIMED}.key 4096
# Remove passphrase
openssl rsa -in client.${USER_DCRTIMED}.key -out client.${USER_DCRTIMED}.key

chmod og-rwx client.${USER_DCRTIMED}.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key client.${USER_DCRTIMED}.key \
    -subj "/CN=${USER_DCRTIMED}" \
    -out client.${USER_DCRTIMED}.csr

# Create client certificate
openssl \
    x509 -req \
    -in client.${USER_DCRTIMED}.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out client.${USER_DCRTIMED}.crt

# Copy client to certs dir
cp client.${USER_DCRTIMED}.key client.${USER_DCRTIMED}.crt root.crt \
  ${POSTGRES_DIR}/certs/clients/${USER_DCRTIMED}

# "On Unix systems, the permissions on 
# server.key must disallow any access to world or group"
# Source: PostgresSQL docs - link above
#
sudo chmod og-rwx $PGDATA/server.key
sudo chmod og-rwx $POSTGRES_DIR/certs/clients/${USER_DCRTIMED}/client.${USER_DCRTIMED}.key

# Cleanup
rm *.crt *.key *.srl *.csr

# Restart postgres to load server certs
sudo -u postgres pg_ctl -D $PGDATA restart

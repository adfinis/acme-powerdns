#!/bin/sh

cd "$(readlink -f "$(dirname "$0")/..")" || exit 1

if [ ! -e .testdata/.venv ]; then
    mkdir -p /host/.testdata/.venv
    python3 -m venv --without-pip .testdata/.venv
    # shellcheck disable=SC1091
    . .testdata/.venv/bin/activate
    python .testdata/get-pip.py
fi

if [ ! -f .testdata/cert.pem ]; then
    cat <<__EOF__ > .testdata/x509.ext
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
default_bits = 4096

[req_distinguished_name]
C  = CH
ST = Bern
L  = Bern
O  = Adfinis SyGroup AG
OU = Test
CN = www.example.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.example.com
DNS.2 = mail.example.com
__EOF__
    openssl genrsa -out .testdata/privkey.pem 4096
    openssl req -new -config .testdata/x509.ext -key .testdata/privkey.pem -sha256 -out .testdata/cert.csr
fi

make test

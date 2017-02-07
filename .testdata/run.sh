#!/bin/sh

# cd to project directory
cd "$(readlink -f "$(dirname "$0")/..")" || exit 1

# create virtualenv
if [ ! -e .testdata/.venv ]; then
    mkdir -p /host/.testdata/.venv
    python3 -m venv --without-pip .testdata/.venv
    # shellcheck disable=SC1091
    . .testdata/.venv/bin/activate
    python .testdata/get-pip.py
fi

# create certificate stuff
mkdir -p .testdata/www.example.com
if [ ! -f .testdata/www.example.com/cert.pem ]; then

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

    openssl genrsa -out .testdata/account.key 4096
    openssl req -new -sha256 -nodes -newkey rsa:4096 \
        -config .testdata/x509.ext \
        -keyout .testdata/live/www.example.com/privkey.pem \
        -out .testdata/csr/www.example.com.csr
fi

make test

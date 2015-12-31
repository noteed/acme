#! /bin/bash

DOMAIN=$1

mkdir -p ${DOMAIN}
openssl genrsa 4096 > ${DOMAIN}/domain.key
openssl req -new -sha256 -key ${DOMAIN}/domain.key -subj "/CN=${DOMAIN}" \
  > ${DOMAIN}/domain.csr
openssl req -in ${DOMAIN}/domain.csr -outform DER > ${DOMAIN}/domain.der

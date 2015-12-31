#! /bin/bash

DOMAIN=$1

openssl x509 -inform der -in ${DOMAIN}/domain.cert.der \
  -out ${DOMAIN}/domain.cert.pem
openssl dhparam -out ${DOMAIN}/dhparams.pem 2048
cat ${DOMAIN}/domain.cert.pem \
  lets-encrypt-x1-cross-signed.pem \
  ${DOMAIN}/domain.key \
  ${DOMAIN}/dhparams.pem > ${DOMAIN}/${DOMAIN}.combined.pem

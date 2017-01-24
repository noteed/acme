#! /bin/bash

DOMAIN=$1

openssl x509 -inform der -in ${DOMAIN}/domain.cert.der \
  -out ${DOMAIN}/domain.cert.pem

AUTHORITY_X=$(openssl x509 -in ${DOMAIN}/domain.cert.pem -text -noout | grep 'Authority X' | awk '{ print $NF }')
AUTHORITY_X_lower="$(echo ${AUTHORITY_X} | awk '{ print tolower($NF) }')"
echo Generating dhparam for HAPRoxy certificate...
openssl dhparam -out ${DOMAIN}/dhparams.pem 2048 > /dev/null 2>&1
echo Creating HAPRoxy certificate using Authority ${AUTHORITY_X}...

case ${AUTHORITY_X_lower} in
  x1)
  # Fine.
  ;;
  x2)
  echo TODO Add an Authority X2 certificate
  exit 1
  ;;
  x3)
  # Fine.
  ;;
  *)
  echo Unkown Authority ${AUTHORITY_X}.
  exit 1
  ;;
esac

cat ${DOMAIN}/domain.cert.pem \
  lets-encrypt-${AUTHORITY_X_lower}-cross-signed.pem \
  ${DOMAIN}/domain.key \
  ${DOMAIN}/dhparams.pem > ${DOMAIN}/${DOMAIN}.combined.pem

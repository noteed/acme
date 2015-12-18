#! /bin/bash
curl -s -i https://acme-v01.api.letsencrypt.org/directory \
  | grep Replay-Nonce \
  | cut -d ' ' -f 2

#! /usr/bin/env bash

docker kill ghcid
docker rm ghcid
docker run \
  --name ghcid \
  -v $(pwd):/source \
  -v $(pwd)/ghci.conf:/home/gusdev/.ghci \
  -t images.reesd.com/reesd/stack:7.8.4 \
  /home/gusdev/.cabal/bin/ghcid --height 30

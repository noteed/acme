#! /bin/bash

docker run \
  -it \
  -v $(pwd):/source \
  images.reesd.com/reesd/stack:7.8.4 \
  sh -c 'cd /source ; ghc --make -threaded -hide-package=crypto-numbers-0.2.7 acme.hs'

rm acme.hi acme.o

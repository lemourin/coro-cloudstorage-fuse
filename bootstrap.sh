#!/usr/bin/env bash

set -e

cd $(dirname $0)

git submodule update --init --recursive

./contrib/coro-cloudstorage/bootstrap.sh

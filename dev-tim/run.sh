#!/bin/bash

container_id=$(docker ps -aqf "name=broker")

# Check if the container is running
if [ -z "$container_id" ]; then
    echo "beam is not running. Please start it using ./dev/beamdev demo in your beam repository"
    exit 1
fi

# Path to your beam repository
export BEAM_DIR=../../beam

export CACHE_PATH=${CACHE_PATH:-"./cache/cache.txt"}

if [ ! -f "$CACHE_PATH" ]; then
    mkdir -p $(dirname "$CACHE_PATH")
    touch "$CACHE_PATH"
fi

delimiter=$'\x1E'
args="OIDC:test-pub:public;http://foo.com,http://bar.com"
args+="$delimiter"
args+="OIDC:test-priv:private;http://foo.com,http://bar.com"
# first=true
# # https://unix.stackexchange.com/a/460466
# for var in "${!SECRET_@}"; do
#     if $first; then
#         args+="keycloak:${var#SECRET_}:${!var}"
#         first=false
#     else
#         args+="${delimiter}keycloak:${var#SECRET_}:${!var}"
#     fi
#     echo "#"
# done

echo "Args: $args"

export ARGS=$args

docker compose up --build

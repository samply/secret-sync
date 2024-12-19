#!/bin/bash

container_id=$(docker ps -aqf "name=broker")

# Check if the beam demo is running
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
args="GitLabProjectAccessToken:foobar:bridgehead-configurations-test/foobar"
args+="$delimiter"
args+="GitLabProjectAccessToken:justatest:bridgehead-configurations-test/just-a-test-project"

echo "Args: $args"

export ARGS=$args

docker compose up "$@"

#!/bin/bash

cd $(dirname "$0")

docker compose down --volumes
docker compose up "$@"
docker compose down --volumes

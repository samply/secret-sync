#! /bin/bash -e

# https://stackoverflow.com/questions/59895/
SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SD=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

cd $SD

container_id=$(docker ps -aqf "name=broker")

# Check if the container is running
if [ -z "$container_id" ]; then
    echo "beam is not running. Please start it using ./dev/beamdev demo in your beam repository"
    exit 1
fi
export BROKER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_id")

container_id=$(docker ps -aqf "name=proxy2")
export PROXY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_id")
export BEAM_DIR=../../beam
echo "Broker running on $BROKER_IP"
echo "Proxy for central running on $PROXY_IP"


export CACHE_PATH=${CACHE_PATH:-"./cache/cache.txt"}

if [ ! -f "$CACHE_PATH" ]; then
    mkdir -p $(dirname "$CACHE_PATH")
    touch "$CACHE_PATH"
fi

compose_arg=""
if [ "$1" = "-b" ]; then
    compose_arg="--build"
    shift
fi

args="OIDC:test:http://foo.com,http://bar.com"
# first=true
# delimiter=$'\x1E'
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

docker compose down && docker compose up $compose_arg

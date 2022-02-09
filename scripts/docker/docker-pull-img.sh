#!/bin/bash -e
# Usage:
#   ./docker-pull-img.sh [docker pull parameters] -- [:TAG|@DIGEST]

SCRIPTS_DIR=${0%/*}
. "$SCRIPTS_DIR"/docker-env-common.sh

docker_pull_callback() {
    local DOCKER_PULL_PARAMS="$1"
    local TAG_DIGEST_PARAMS="$2"
    REGISTRY_DOCKER_IMAGE_TAG_WITH_DIGEST="$REGISTRY_DOCKER_IMAGE_TAG$TAG_DIGEST_PARAMS"
    local COMMAND="docker pull $DOCKER_PULL_PARAMS $REGISTRY_DOCKER_IMAGE_TAG_WITH_DIGEST"
    echo $COMMAND
    $COMMAND
}

delete_image "$DOCKER_IMAGE_TAG"
split_params docker_pull_callback "$@"
docker tag "$REGISTRY_DOCKER_IMAGE_TAG_WITH_DIGEST" "$DOCKER_IMAGE_TAG"


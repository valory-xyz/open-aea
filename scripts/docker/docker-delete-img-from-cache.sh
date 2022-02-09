#!/bin/bash -e

SCRIPTS_DIR=${0%/*}
. "$SCRIPTS_DIR"/docker-env-common.sh

delete_image "$DOCKER_IMAGE_TAG"
delete_image "$REGISTRY_DOCKER_IMAGE_TAG"
delete_dangling_layers


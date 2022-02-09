#!/bin/bash -e

SCRIPTS_DIR=${0%/*}

"$SCRIPTS_DIR"/docker-add_registry-cred-helpers.py

"$SCRIPTS_DIR"/docker-delete-img-from-cache.sh
"$SCRIPTS_DIR"/docker-build-img.sh --no-cache --

if [[ "$PUBLISH_IMAGE_TO_DOCKER_REGISTRY" == "true" ]]
then
    "$SCRIPTS_DIR"/docker-publish-img.sh
else
    echo "The image has *NOT* been pushed to the docker registry because PUBLISH_IMAGE_TO_DOCKER_REGISTRY=$PUBLISH_IMAGE_TO_DOCKER_REGISTRY." 
fi

"$SCRIPTS_DIR"/docker-delete-img-from-cache.sh


#!/bin/bash -e
# Usage:
#   ./docker-run.sh <docker parameters> -- <executable> <executable parameters>
# Examples:
#   # The following example provides the `--cpus 4` parameter to `docker run` command (sets number of available CPUs for docker run) and executes `make -j http_server` executable with parameters inside of the docker container
#   ./docker-run.sh --cpus 4 -- make -j http_server
#
#   # The following example provides `-p 8080:8080` parameter to `docker run` command (exports inner docker network port 8080 to outer(host OS) port 8080) and excutes `http_server` executable inside of the docker container:
#   ./docker-run.sh -p 8080:8080 -- build/examples/http_server
# NOTE: For more details, please see description for the `split_params()` shell function in the `docker-common.sh` script.

SCRIPTS_DIR=${0%/*}
. "$SCRIPTS_DIR"/docker-env-common.sh

docker_run_callback() {
    local DOCKER_PARAMS="$1"
    local EXECUTABLE_PARAMS="$2"
    local COMMAND="docker run -i $USE_TTY -w $WORKDIR --rm $DOCKER_PARAMS -v $(pwd):$WORKDIR $DOCKER_IMAGE_TAG $EXECUTABLE_PARAMS"
    echo $COMMAND
    $COMMAND
}

split_params docker_run_callback "$@"


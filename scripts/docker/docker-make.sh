#!/bin/bash -e
# Usage:
#   ./docker-make.sh <docker parameters> -- <parameters for make>
# Examples:
#   # The following example provides the `--cpus 4` parameter to `docker run` command (sets number of available CPUs for docker run) and executes make with `-j http_server` parameters inside of the docker container
#   ./docker-make.sh --cpus 4 -- http_server
#
# NOTE: For more details, please see description for the `split_params()` shell function in the `docker-common.sh` script.

SCRIPTS_DIR=${0%/*}
. "$SCRIPTS_DIR"/docker-env-common.sh

docker_run_callback() {
    local DOCKER_PARAMS="$1"
    local MAKE_PARAMS="$2"
    local COMMAND="$SCRIPTS_DIR/docker-run.sh $DOCKER_PARAMS -- $DOCKER_LOCAL_MAKE $MAKE_PARAMS"
    echo $COMMAND
    $COMMAND
}

split_params docker_run_callback "$@"


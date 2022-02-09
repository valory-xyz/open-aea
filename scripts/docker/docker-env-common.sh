#!/bin/bash -e
 
##############################################################################
# ####  PRIVATE section  #####################################################
# Shall **not** be overriden in DOCKER_ENV_SCRIPT file.
if [[ -z ${SCRIPTS_DIR+x} ]]
then
    SCRIPTS_DIR=${0%/*}
fi

SCRIPTS_PARENT_DIR="$(dirname "$SCRIPTS_DIR")"

. "$SCRIPTS_DIR"/docker-common.sh

##############################################################################
# ####  PUBLIC section  ######################################################
# Env vars in this section can or must be overriden in DOCKER_ENV_SCRIPT file.

# Following variables **MUST** be defined in DOCKER_ENV_SCRIPT file.
DOCKER_IMAGE_TAG=

# Following variables **CAN** be overriden in DOCKER_ENV_SCRIPT file.
DOCKER_CONTAINER_REGISTRY=gcr.io/organic-storm-201412
DOCKER_BUILD_CONTEXT_DIR=
DOCKERFILE=
# The 'DOCKER_LOCAL_MAKE' must be etiher absolut path or relative to the working directory 'WORKDIR' in the running docker container environment!
DOCKER_LOCAL_MAKE=
WORKDIR=/build

##############################################################################
# ####  PRIVATE section  #####################################################
# Env vars set here shall **not** be overriden in DOCKER_ENV_SCRIPT file.
DOCKER_ENV_SCRIPT=docker-env.sh
DOCKER_ENV_SCRIPT_PATH="$SCRIPTS_PARENT_DIR/$DOCKER_ENV_SCRIPT"
test -t 1 && USE_TTY="-t"

if [ -f "$DOCKER_ENV_SCRIPT_PATH" ]; then
    . "$DOCKER_ENV_SCRIPT_PATH"
else
    echo "WARNING: The '$DOCKER_ENV_SCRIPT_PATH' file does not exist."
fi

REGISTRY_DOCKER_IMAGE_TAG="$DOCKER_CONTAINER_REGISTRY"/"$DOCKER_IMAGE_TAG"

if [ -n "${DOCKERFILE}" ]
then
    DOCKERFILE="$(add_parent_to_relative_path "$DOCKERFILE" "$SCRIPTS_PARENT_DIR")"
fi

DOCKER_BUILD_CONTEXT_DIR="$(add_parent_to_relative_path "$DOCKER_BUILD_CONTEXT_DIR" "$SCRIPTS_PARENT_DIR")"

# The script/executable file defined by the 'DOCKER_LOCAL_MAKE' path must be available in the running docker container environment!
if [ -n "${DOCKER_LOCAL_MAKE}" ]
then
    DOCKER_LOCAL_MAKE="$(add_parent_to_relative_path "$DOCKER_LOCAL_MAKE" "$SCRIPTS_PARENT_DIR")"
else
    DOCKER_LOCAL_MAKE="$(add_parent_to_relative_path "docker-local-make.sh" "$SCRIPTS_DIR")"
fi
DOCKER_LOCAL_MAKE_ABS="$(abs_path "$DOCKER_LOCAL_MAKE")"
# Here we assume that the DOCKER_LOCAL_MAKE is availabe in volume filesystem mounted in runnig docker container (that's why we use here "$(pwd)", since the $(pwd) directory will be mounted to the container).
DOCKER_LOCAL_MAKE=${DOCKER_LOCAL_MAKE_ABS#"$(pwd)/"}

check_env() {
    if [ -n "${DOCKER_ENV_CHECKED}" ]
    then
        return 0
    fi

    DOCKER_ENV_CHECKED=true

    echo ["$DOCKER_ENV_SCRIPT"] DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:?"It is neccessary to set the DOCKER_IMAGE_TAG env var in the '$DOCKER_ENV_SCRIPT_PATH' file and it must be set to non-empty value"}"
    echo ["$DOCKER_ENV_SCRIPT"] DOCKER_CONTAINER_REGISTRY="${DOCKER_CONTAINER_REGISTRY:?"It is neccessary to set the DOCKER_CONTAINER_REGISTRY env var in the '$DOCKER_ENV_SCRIPT_PATH' file, and it must be set to non-empty value"}"
    echo ["$DOCKER_ENV_SCRIPT"] DOCKER_LOCAL_MAKE="${DOCKER_LOCAL_MAKE:?"The DOCKER_LOCAL_MAKE env var is not set. It looks like it has been uset (or set to empty value) in the '$DOCKER_ENV_SCRIPT_PATH' file."}"

    echo ["$DOCKER_ENV_SCRIPT"] pwd="$(pwd)"
    echo ["$DOCKER_ENV_SCRIPT"] DOCKER_BUILD_CONTEXT_DIR="$DOCKER_BUILD_CONTEXT_DIR"
    echo ["$DOCKER_ENV_SCRIPT"] DOCKERFILE="$DOCKERFILE"
    echo ["$DOCKER_ENV_SCRIPT"] DOCKER_ENV_SCRIPT_PATH="$DOCKER_ENV_SCRIPT_PATH"
    echo ["$DOCKER_ENV_SCRIPT"] http_proxy =$http_proxy
    echo ["$DOCKER_ENV_SCRIPT"] https_proxy=$https_proxy
    echo ["$DOCKER_ENV_SCRIPT"] no_proxy=$no_proxy
}

check_env


#!/bin/bash -e

#############################################################################
# #### **MANDATORY** variables section
# Variables in this section **MUST** be set in `docker-env.sh` file

# ---------------------------------------------------------------------------
# This variable defines docker image tag (*WIHOUT* container registry URI prefix).
# Example: DOCKER_IMAGE_TAG=fetch-ledger-develp:latest
DOCKER_IMAGE_TAG=


#############################################################################
# #### **NON**-mandatory variables
# They **can** be overriden in this file. Their default value is defined by scripts insfrastructure.

# ---------------------------------------------------------------------------
# This variable defines URI of docker image **registry** where newly created
# images will be pushed in to, or pulled from (by `docker-publish-img.sh` and
# `docker-pull-img.sh` scripts).
# It defaults to `gcr.io/organic-storm-201412` (it's fetch.ai private project on google cloud):
#DOCKER_CONTAINER_REGISTRY=

# ---------------------------------------------------------------------------
# This variable defines the context directory for docker build (used by the 
# `docker-build-img.sh` script).
# This means that docker build process will have access exclusivelly to this 
# directory on **host OS** during build process (irelevant for COPY and ADD
# instructions in dockerfile). Host OS filesystem beyond this directory, what 
# means parent folders, will **NOT** be accessible during docker build process.
# It defaults to the **very same** directory where `docker-env.sh` file is
# located.
#DOCKER_BUILD_CONTEXT_DIR=

# ---------------------------------------------------------------------------
# This variable Defines path to custom dockerfile.
# It defaults to the `Dockerfile` file located in the DOCKER_BUILD_CONTEXT_DIR
# dicrectory, as this is implicit behaviour of the `docker` command when
# dockerfile is **NOT** explicitly provided.
#DOCKERFILE=

# ---------------------------------------------------------------------------
# This variable defines path to executable/script which executes/manages build,
# what is usually the `make`.
# This variable is used exclusivelly by the `scripts/docker-make.sh` script,
# so it does **not** affect other scripts.
# It must be either relative path to the directory where `docker-env.sh` is
# located in the running docker container filesystem, or absolute path (agan
# in filesystem of the running docker container).
# NOTE: This assumes that this executable/script will be present on the
# filesystem of running docker container environment (at the location 
# specified by this env var)!
# It defaults to the reative path `scripts/docker-local-make.sh` script.
#DOCKER_LOCAL_MAKE=

# ---------------------------------------------------------------------------
# This variable defines directory in the running docker container (**not** on host OS),
# in to which a volume will be mounted by `docker-run.sh` script.
# The volume is defined by current working directory on **host OS** where
# the `docker-run.sh` script is excuted.
# Defaults to `/docker`.
#WORKDIR=


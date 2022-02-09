#!/bin/bash -e

SCRIPTS_DIR=${0%/*}
. "$SCRIPTS_DIR"/docker-common.sh

delete_dangling_layers


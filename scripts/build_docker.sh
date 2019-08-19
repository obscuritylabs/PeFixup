#!/usr/bin/env bash
set -e
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=obscuritylabs
# image name
IMAGE=pefixup
docker build -t $USERNAME/$IMAGE:latest .
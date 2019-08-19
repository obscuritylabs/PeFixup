#!/usr/bin/env bash
set -e

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

VERSION=`cat VERSION`
echo "---------------------------------------------"
echo "| Building pefixup Docker version: $VERSION |"
echo "---------------------------------------------"
./build_docker.sh

# DOCKER TAG/VERSIONING
docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$VERSION

# PUSH TO DOCKER HUB
docker push $USERNAME/$IMAGE:latest
echo "------------------------------------------------"
echo "| Docker image pushed: $USERNAME/$IMAGE:latest |"
echo "------------------------------------------------"
docker push $USERNAME/$IMAGE:$VERSION
echo "--------------------------------------------------"
echo "| Docker image pushed: $USERNAME/$IMAGE:$VERSION |"
echo "--------------------------------------------------"
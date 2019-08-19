#!/usr/bin/env bash
set -e

git_sha="$(git rev-parse --short HEAD)"
echo "--------------------------------------"
echo "| Current git sha: ${git_sha}        |"
echo "| Current git branch: $TRAVIS_BRANCH |"
echo "--------------------------------------"

VERSION=`cat VERSION`
echo "---------------------------------------------"
echo "| Building pefixup Docker version: $VERSION |"
echo "---------------------------------------------"
./scripts/build_docker.sh

# DOCKER TAG/VERSIONING
docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$VERSION

# PUSH TO DOCKER HUB
if [[ "$TRAVIS_BRANCH" == "master" ]]; then
    docker push $USERNAME/$IMAGE:latest
	echo "------------------------------------------------"
	echo "| Docker image pushed: $USERNAME/$IMAGE:latest |"
	echo "------------------------------------------------"
	docker push $USERNAME/$IMAGE:$VERSION
	echo "--------------------------------------------------"
	echo "| Docker image pushed: $USERNAME/$IMAGE:$VERSION |"
	echo "--------------------------------------------------"
fi
if [[ "$TRAVIS_BRANCH" == "development" ]]; then
    docker push $USERNAME/$IMAGE:development
	echo "------------------------------------------------"
	echo "| Docker image pushed: $USERNAME/$IMAGE:latest |"
	echo "------------------------------------------------"
	docker push $USERNAME/$IMAGE:${git_sha}-development
	echo "----------------------------------------------------------------"
	echo "| Docker image pushed: $USERNAME/$IMAGE:${git_sha}-development |"
	echo "----------------------------------------------------------------"
fi
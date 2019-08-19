#!/usr/bin/env bash
set -ex

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

# PUSH TO DOCKER HUB
if [[ "$TRAVIS_BRANCH" == "master" ]]; then
	# DOCKER TAG/VERSIONING
	docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$VERSION
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
	# DOCKER TAG/VERSIONING
	docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$development
	docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:${git_sha}-development
    docker push $USERNAME/$IMAGE:development
	echo "-----------------------------------------------------"
	echo "| Docker image pushed: $USERNAME/$IMAGE:development |"
	echo "-----------------------------------------------------"
	docker push $USERNAME/$IMAGE:${git_sha}-development
	echo "----------------------------------------------------------------"
	echo "| Docker image pushed: $USERNAME/$IMAGE:${git_sha}-development |"
	echo "----------------------------------------------------------------"
fi
#!/bin/sh
export KO_DOCKER_REPO="gcr.io/kolide/pipeline-notifier"

gcloud run deploy pipeline-notifier --image="$(ko publish .)" --args=-serve \
  --region us-east4 --project kolide
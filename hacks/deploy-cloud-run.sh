#!/bin/sh
PROJECT="kolide-357616"
export KO_DOCKER_REPO="gcr.io/${PROJECT}/pipeline-notifier"

gcloud run deploy pipeline-notifier --image="$(ko publish .)" --args=-serve \
  --region us-central1 --project "${PROJECT}"
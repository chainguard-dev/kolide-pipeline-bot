# kolide-pipeline-bot

Send notifications from osquery differential logs uploaded to GCP storage by Kolide

## Features

* Support for Kolide differential logs
* Rich Slack notifications
* VirusTotal annotation
* Google Cloud Storage
* CLI and HTTP server modes
* Duplicate event suppression
* Threading of related events

## Usage

Compile:

```shell
go build .
```

Setup your local credentials:

```shell
gcloud auth application-default login
```

Inspect output without sending notifications:

```shell
kolide-pipeline-bot \
  --bucket=your-kolide-logs \
  --prefix=kolide/results/threat_hunting \
  --max-age=8h
```

To send notifications, set a SLACK_ACCESS_TOKEN to a Bot User OAuth Token for your Workspace, which typically starts with `xoxb-`. 

## Webserver mode

This will run a web server, that will scan the bucket every time `/refreshz` is hit, as well as send notifications:

```shell
kolide-pipeline-bot \
  --bucket=your-osquery-logs \
  --prefix=kolide/results/threat_hunting \
  --serve
```

This allows the kolide-pipeline-bot to be run in environments that assume an HTTP frontend, such as Google Cloud Run. You can then use a scheduler service to hit `/refreshz` as often as you want to poll for results.

## Environment Variables

For your deployment, you may find it more useful to use environment variables than arguments. The `kolide-pipeline-bot` supports a handful of them:

* `PORT`
* `BUCKET_NAME`
* `BUCKET_PREFIX`
* `SLACK_ACCESS_TOKEN`
* `VIRUSTOTAL_KEY`

## Google Cloud Run

Using `ko`, it is easy to build `kolide-pipeline-notifier` to your local repo and deploy it straight into production:

```shell
export KO_DOCKER_REPO="gcr.io/<your project>/pipeline-notifier"

gcloud run deploy pipeline-notifier \
  --image="$(ko publish .)" \
  --args=-serve \
  --region us-central1 \
  --project "<your project>"
```

You can see an example automated deployment in `./hacks/deploy-cloud-run.sh`

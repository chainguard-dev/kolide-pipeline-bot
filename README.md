# kolide-pipeline-notifier

Send notifications when Kolide Pipeline outputs change

## Features

* Rich Slack notifications
* Google Cloud Storage
* CLI and HTTP server modes
* Duplicate event suppression

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
kolide-pipeline-notifier \
  --bucket=your-kolide-logs \
  --prefix=kolide/results/threat_hunting \
  --max-age=8h
```

To send notifications, add your Slack `--webhook-url`

## Webserver mode

This will run a web server, that will scan the bucket every time `/refreshz` is hit, as well as send notifications:

```shell
kolide-pipeline-notifier \
  --bucket=your-kolide-logs \
  --prefix=kolide/results/threat_hunting \
  --webhook-url=https://hooks.slack.com/services/oaeuSAOENTU/OESUNTOEU \
  --serve
```

This allows the kolide-pipeline-notifier to be run in environments that assume an HTTP frontend, such as Google Cloud Run. You can then use a scheduler service to hit `/refreshz` as often as you want to poll for results.

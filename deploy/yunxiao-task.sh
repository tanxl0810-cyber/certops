#!/bin/sh
set -eu
: "${CERTOPS_JOB_ID:?Task identifier is required}"
: "${CERTOPS_ATTEMPT_ID:?Attempt identifier is required}"
python3 /usr/local/libexec/certops-pipeline.py --config /etc/certops/pipeline.json

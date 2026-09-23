#!/bin/sh
set -eu
if [ "$#" -eq 0 ]; then
  exec /usr/local/bin/tu1nz_doc_pipeline.py --stage
fi
exec /usr/local/bin/tu1nz_doc_pipeline.py "$@"

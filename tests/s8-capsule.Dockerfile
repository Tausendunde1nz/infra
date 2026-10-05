# PRIVATE BUILD CONTEXT ONLY: the resulting image contains private Application
# source. Never build/upload it in the public Control repository's workflow.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv git systemd ca-certificates && apt-get clean
COPY application /application
COPY control /control
ARG APPLICATION_COMMIT
ARG APPLICATION_TREE
RUN python3 -m venv /runtime && \
    /runtime/bin/python -I -B -m pip install --no-cache-dir --require-hashes \
      -r /application/requirements-m2.lock -r /application/requirements-s5.lock && \
    /runtime/bin/python -I -B /control/tu1nz_s8_capsule_finalize.py \
      "$APPLICATION_COMMIT" "$APPLICATION_TREE"
WORKDIR /application
ENTRYPOINT ["/usr/bin/python3", "-I", "-B", "-S", "/control/tu1nz_s8_capsule_bootstrap.py"]

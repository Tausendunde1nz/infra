FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ENV DEBIAN_FRONTEND=noninteractive
# Build-time public distribution packages only. No private Source, Host data,
# keys, provider input or host-manager socket is ever copied into this image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 git openssl acl systemd systemd-sysv dbus util-linux e2fsprogs \
    procps ca-certificates postgresql-16 postgresql-client-16 sudo polkitd nginx \
    && apt-get clean
STOPSIGNAL SIGRTMIN+3
COPY tests/s8_native_init.py /s8_native_init.py
CMD ["/usr/bin/python3", "-I", "-B", "/s8_native_init.py"]

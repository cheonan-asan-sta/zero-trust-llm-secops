ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 qemu-utils cloud-image-utils openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 AWS_EC2_METADATA_DISABLED=true
WORKDIR /tmp
ENTRYPOINT ["python"]

ARG LAMBDA_NAME
ARG ADOT_VERSION=0.15.0
ARG ADOT_LAYER_SHA256=f71f957f72a7756ba8c253ef9ca5c5f33a774a0da02d12dad30f22e0637c2672
FROM ghcr.io/astral-sh/uv:0.5 AS uv

FROM public.ecr.aws/lambda/python:3.13-arm64 AS builder
ARG LAMBDA_NAME
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1
ENV UV_NO_INSTALLER_METADATA=1
ENV UV_LINK_MODE=copy

WORKDIR /app
COPY ${LAMBDA_NAME}/pyproject.toml ${LAMBDA_NAME}/uv.lock ./
RUN uv sync --frozen --no-dev --no-editable

COPY ${LAMBDA_NAME}/src/ ./src/

FROM public.ecr.aws/lambda/python:3.13-arm64 AS adot
ARG ADOT_VERSION
ARG ADOT_LAYER_SHA256
COPY --from=uv /uv /usr/local/bin/uv

# Extract only scripts from layer.zip (otel-instrument + otel_wrapper.py)
RUN dnf install -y unzip && \
    curl -L -o /tmp/layer.zip \
    "https://github.com/aws-observability/aws-otel-python-instrumentation/releases/download/v${ADOT_VERSION}/layer.zip" && \
    echo "${ADOT_LAYER_SHA256}  /tmp/layer.zip" | sha256sum -c - && \
    mkdir -p /opt/python/bin && \
    unzip -j /tmp/layer.zip "otel-instrument" -d /opt/ && \
    unzip -j /tmp/layer.zip "python/otel_wrapper.py" -d /opt/python/ && \
    chmod 755 /opt/otel-instrument && \
    rm /tmp/layer.zip

# Install ADOT packages via uv lockfile (pinned transitive deps with hashes)
WORKDIR /adot
COPY adot/pyproject.toml adot/uv.lock ./
RUN uv sync --frozen --no-dev --no-editable --no-install-project && \
    cp -r .venv/lib/python3.13/site-packages/* /opt/python/

# Create opentelemetry-instrument entry point via package metadata
# (otel-instrument wrapper calls python3 /opt/python/bin/opentelemetry-instrument)
RUN printf '#!/usr/bin/env python3\nfrom importlib.metadata import entry_points\nnext(iter(entry_points(group="console_scripts", name="opentelemetry-instrument"))).load()()\n' \
    > /opt/python/bin/opentelemetry-instrument && \
    chmod 755 /opt/python/bin/opentelemetry-instrument

FROM public.ecr.aws/lambda/python:3.13-arm64
ARG LAMBDA_NAME
# Append to PYTHONPATH to preserve base image's /var/lang
ENV PYTHONPATH="/opt/python${PYTHONPATH:+:${PYTHONPATH}}"
COPY --from=adot /opt/otel-instrument /opt/otel-instrument
COPY --from=adot /opt/python /opt/python
COPY --from=builder /app/.venv/lib/python3.13/site-packages ${LAMBDA_TASK_ROOT}
COPY --from=builder /app/src/${LAMBDA_NAME} ${LAMBDA_TASK_ROOT}

CMD ["handler.handler"]

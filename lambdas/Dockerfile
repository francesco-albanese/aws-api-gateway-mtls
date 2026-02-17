ARG LAMBDA_NAME
ARG ADOT_VERSION=0.15.0
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
COPY --from=uv /uv /usr/local/bin/uv

# Extract only scripts from layer.zip (otel-instrument + otel_wrapper.py)
RUN dnf install -y unzip && \
    curl -L -o /tmp/layer.zip \
    "https://github.com/aws-observability/aws-otel-python-instrumentation/releases/download/v${ADOT_VERSION}/layer.zip" && \
    mkdir -p /opt/python/bin && \
    unzip -j /tmp/layer.zip "otel-instrument" -d /opt/ && \
    unzip -j /tmp/layer.zip "python/otel_wrapper.py" -d /opt/python/ && \
    chmod 755 /opt/otel-instrument && \
    rm /tmp/layer.zip

# Install ADOT packages via uv (compiled for Python 3.13 ARM64)
RUN uv pip install --system --target /opt/python \
    aws-opentelemetry-distro \
    opentelemetry-instrumentation-aws-lambda

# Create opentelemetry-instrument entry point
# (otel-instrument script calls python3 /opt/python/bin/opentelemetry-instrument)
RUN printf '#!/usr/bin/env python3\nfrom opentelemetry.instrumentation.auto_instrumentation import run\nrun()\n' \
    > /opt/python/bin/opentelemetry-instrument && \
    chmod 755 /opt/python/bin/opentelemetry-instrument

FROM public.ecr.aws/lambda/python:3.13-arm64
ARG LAMBDA_NAME
COPY --from=adot /opt/otel-instrument /opt/otel-instrument
COPY --from=adot /opt/python /opt/python
COPY --from=builder /app/.venv/lib/python3.13/site-packages ${LAMBDA_TASK_ROOT}
COPY --from=builder /app/src/${LAMBDA_NAME} ${LAMBDA_TASK_ROOT}

CMD ["handler.handler"]

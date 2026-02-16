ARG LAMBDA_NAME
ARG ADOT_VERSION=0.14.0
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

FROM public.ecr.aws/lambda/python:3.13-arm64 AS adot-layer
ARG ADOT_VERSION
RUN dnf install -y unzip && \
    curl -L -o /tmp/layer.zip \
    "https://github.com/aws-observability/aws-otel-python-instrumentation/releases/download/v${ADOT_VERSION}/layer.zip" && \
    mkdir -p /opt && \
    unzip /tmp/layer.zip -d /opt/ && \
    chmod -R 755 /opt/ && \
    rm /tmp/layer.zip

FROM public.ecr.aws/lambda/python:3.13-arm64
ARG LAMBDA_NAME
COPY --from=adot-layer /opt /opt
COPY --from=builder /app/.venv/lib/python3.13/site-packages ${LAMBDA_TASK_ROOT}
COPY --from=builder /app/src/${LAMBDA_NAME} ${LAMBDA_TASK_ROOT}

# CRITICAL: Ensure otel_wrapper and the distro packages are on PYTHONPATH
ENV PYTHONPATH="/opt/python:/opt:${LAMBDA_TASK_ROOT}"

CMD ["handler.handler"]

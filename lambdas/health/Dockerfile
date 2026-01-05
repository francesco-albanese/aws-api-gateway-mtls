FROM ghcr.io/astral-sh/uv:0.5 AS uv

FROM public.ecr.aws/lambda/python:3.13-arm64 AS builder
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1
ENV UV_NO_INSTALLER_METADATA=1
ENV UV_LINK_MODE=copy

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-editable

COPY src/ ./src/

FROM public.ecr.aws/lambda/python:3.13-arm64
COPY --from=builder /app/.venv/lib/python3.13/site-packages ${LAMBDA_TASK_ROOT}
COPY --from=builder /app/src/health ${LAMBDA_TASK_ROOT}

CMD ["handler.handler"]

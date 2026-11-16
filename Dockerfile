ARG PYTHON_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
COPY requirements.txt ./
RUN python -m pip download --only-binary=:all: --require-hashes -r requirements.txt -d /wheels
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="AntiCNSpy" \
      org.opencontainers.image.version="1.1.0" \
      org.opencontainers.image.description="Strict software release signing and verification" \
      org.opencontainers.image.source="https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels anticnspy==1.1.0 \
    && rm -rf /wheels
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["anticnspy"]
CMD ["--help"]

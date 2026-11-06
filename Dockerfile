# OSV-Scanner v2.3.0, pinned per architecture to the release's SHA-256 values.
# ADD --checksum fails the build on any mismatch.
FROM scratch AS osv-scanner-amd64
ADD --checksum=sha256:e774e5770c31d60745c067be5f69bf3b46641b6d0e0ed87fd65e569cda35dc50 \
    https://github.com/google/osv-scanner/releases/download/v2.3.0/osv-scanner_linux_amd64 \
    /osv-scanner

FROM scratch AS osv-scanner-arm64
ADD --checksum=sha256:68da4208d90436d75ee669fa5ea6969949b78ecd29330f16a87976333bef3b88 \
    https://github.com/google/osv-scanner/releases/download/v2.3.0/osv-scanner_linux_arm64 \
    /osv-scanner

FROM osv-scanner-${TARGETARCH} AS osv-scanner

FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /usr/local/bin/uv
# Root-owned and not writable by the runtime user; the CLI's default executable.
COPY --from=osv-scanner --chmod=0755 /osv-scanner /usr/local/bin/osv-scanner

WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    uv sync --locked --no-dev --no-editable \
    && groupadd --system app \
    && useradd --system --gid app --no-create-home app \
    && install -d -o app -g app -m 0700 /out

USER app
EXPOSE 8000
CMD ["uvicorn", "remediator.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

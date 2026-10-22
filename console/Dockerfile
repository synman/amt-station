# amt-console: the management console's backend and static client. Built by deploy/compose.yaml.
# Build from the repository root:  docker build -f console/Dockerfile .   (deploy/compose.yaml does this)
# The base image is pinned by tag, as the amt-mcp image is (a digest pin needs a registry lookup, owed at deploy time).
FROM python:3.12.7-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AMT_CONSOLE_BIND=0.0.0.0 \
    AMT_CONSOLE_PORT=8767

COPY console/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && useradd --create-home --uid 10001 console

WORKDIR /app
COPY console/server.py console/auth.py console/captures.py console/embed.py console/fleet.py console/images.py console/intake.py console/mcp_client.py console/power.py console/webauthn_min.py ./
COPY console/pages ./pages
COPY console/static ./static

USER console
EXPOSE 8767

# No secret is baked in or defaulted. The console's bearer is read at run time from its own vault, mounted read-only
# (see deploy/compose.yaml) and reached through AMT_CONSOLE_SECRETS_CLI; there is no default CLI path on purpose.
CMD ["python", "server.py"]

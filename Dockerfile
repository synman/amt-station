# amt-mcp: gated streamable-HTTP MCP server. Built by deploy/compose.yaml.
# The base image is pinned by tag (a digest pin needs a registry lookup, owed at deploy time).
# mcp is pinned to the version this skeleton was developed against; per the fleet gate
# convention (Wave 5/6 trap 3) re-verify it against the deploy target's venv before shipping.
FROM python:3.12.7-slim-bookworm

ARG MCP_VERSION=1.26.0
ARG PILLOW_VERSION=12.1.1
# cryptography is for the mounted node-vault-mcp secrets.py, which amt_vault runs as a child.
ARG CRYPTOGRAPHY_VERSION=46.0.3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AMT_BIND_HOST=0.0.0.0 \
    AMT_PORT=8765

# amt_remote_logon / amt_remote_logoff type only into a screen positively identified by OCR
# (amt_tools.ocr_fragments), so the image needs the tesseract binary and Pillow; without them
# both tools fail closed (reason "ocr_unavailable") and type nothing. Dev on macOS uses
# `pip install ocrmac` instead. The apt packages are not version-pinned on purpose: the base
# image tag fixes the Debian release, and Debian removes superseded package versions from its
# mirrors, so an exact apt pin breaks the next rebuild instead of protecting it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr ffmpeg \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "mcp==${MCP_VERSION}" "pillow==${PILLOW_VERSION}" "cryptography==${CRYPTOGRAPHY_VERSION}" \
    && useradd --create-home --uid 10001 amt

WORKDIR /app
COPY amt_server.py amt_gate.py amt_registry.py amt_vault.py amt_parity.py amt_kvm.py amt_wsman.py amt_tools.py amt_wsman_write.py amt_redir.py amt_write.py amt_logdecode.py amt_mirror.py amt_serial.py amt_handoff.py amt_upload.py amt_fleet.py amt_identity.py amt_captures.py ./
COPY vendor ./vendor

USER amt
EXPOSE 8765 8766

# No secret is baked in or defaulted. The AMT and host credentials come from a dedicated vault
# mounted at run time and read through AMT_SECRETS_CLI (see deploy/compose.yaml). MCP_ADMIN_TOKEN_HASH (the SHA-256 of the fleet token)
# and AMT_ALLOWED_HOSTS (the ingress Host) are supplied at run time; without the hash the
# server refuses to start.
CMD ["python", "amt_server.py"]

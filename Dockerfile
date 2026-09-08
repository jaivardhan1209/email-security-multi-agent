# ---------------------------------------------------------------------------
# Email-security multi-agent POC.
#
# The image contains NO model. It talks to an Ollama runtime over the network,
# which keeps the image small and lets the same image run against Ollama in
# development and an Azure AI Foundry endpoint in production — the only change
# is LLM_PROVIDER and the credentials injected at runtime.
#
# With no runtime reachable the container still works: it degrades to the
# deterministic tool+rule layer rather than failing (see §16 fail-safe).
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY email_security/ ./email_security/
COPY data/ ./data/
COPY web/ ./web/
COPY app.py server.py ./

# Run as a non-root user: this process parses hostile input by design.
RUN useradd --create-home --uid 10001 analyst && chown -R analyst:analyst /app
USER analyst

# Default configuration. Override at run time:
#   docker run --rm -e LLM_PROVIDER=ollama -e OLLAMA_HOST=http://host.docker.internal:11434 ...
ENV LLM_PROVIDER=offline \
    OLLAMA_HOST=http://host.docker.internal:11434 \
    LOG_FORMAT=json \
    LOG_LEVEL=INFO

HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from email_security.orchestration import build_components; build_components(); print('ok')"

# CLI by default. For the web inspector:
#   docker run --rm -p 8800:8800 --entrypoint python email-security-poc \
#     server.py --host 0.0.0.0
EXPOSE 8800
ENTRYPOINT ["python", "app.py"]
CMD ["evaluate"]

# Container image for the TriageDesk dashboard.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8501

WORKDIR /app

# Run as an unprivileged user rather than root.
RUN useradd --create-home --uid 10001 triagedesk

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[app]"

COPY app ./app
COPY data/samples ./data/samples
COPY .streamlit ./.streamlit

USER triagedesk
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/_stcore/health')"

CMD ["sh", "-c", "streamlit run app/streamlit_app.py --server.port=${PORT} --server.address=0.0.0.0"]

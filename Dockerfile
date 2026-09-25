# Roam Fleet Compliance - Production Container Image
# Zero external pip dependencies - uses Python 3.12 standard library only
FROM python:3.12-alpine

# Set Python to run unbuffered and listen on 0.0.0.0
ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    HOST=0.0.0.0 \
    COMPLIANCE_DB=/app/data/compliance.db

WORKDIR /app

# Create data directory for SQLite database
RUN mkdir -p /app/data

# Copy application assets
COPY agent/ /app/agent/
COPY server/ /app/server/
COPY legal/ /app/legal/
COPY dashboard.html /app/dashboard.html
COPY pc_audit.py /app/pc_audit.py
COPY setup_firewall.sh /app/setup_firewall.sh

# Cloud Run default port is 8080
EXPOSE 8080

# Health check using standard library urllib
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request, os; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8080') + '/api/v1/health')" || exit 1

# Launch the zero-dependency REST server
CMD ["python3", "-m", "server.app"]

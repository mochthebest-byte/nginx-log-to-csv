FROM python:3.12-slim

WORKDIR /app
COPY parser.py /app/parser.py

# Non-root (приємний плюс до security)
RUN useradd -m appuser
USER appuser

ENTRYPOINT ["python", "/app/parser.py"]

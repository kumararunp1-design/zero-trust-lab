FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io && rm -rf /var/lib/apt/lists/*
COPY app.py .
EXPOSE 5601
CMD ["python", "app.py"]

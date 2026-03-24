FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 file && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "until curl -s http://opencti:8080/graphql > /dev/null; do echo 'Waiting for OpenCTI...'; sleep 5; done; python connector.py"]

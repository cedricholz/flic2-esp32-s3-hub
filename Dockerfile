FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Los_Angeles
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    net-tools \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./
RUN poetry install --only main --no-interaction --no-ansi

COPY . ./

CMD ["python3", "main.py"]
FROM python:3.12-slim

WORKDIR /opt/beaconscope
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir .

ENTRYPOINT ["beaconscope"]

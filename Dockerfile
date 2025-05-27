FROM unit:1.34.2-python3.13

WORKDIR /app

COPY requirements.txt .
RUN python3.13 -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip && \
    pip install -r requirements.txt

COPY . .

# Copy the TLS bundle and Unit config
COPY unit/unit.json /docker-entrypoint.d/config.json

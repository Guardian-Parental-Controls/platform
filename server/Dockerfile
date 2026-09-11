FROM python:3.14-slim

WORKDIR /app

# Create instance directory for Flask app data (database)
RUN mkdir -p /app/instance && chmod 777 /app/instance

# Install apksigner for Android MDM APK checksum computation on upload
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-21-jre \
        openssl \
        xxd \
        wget \
        unzip \
    && mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools" \
    && wget -q https://dl.google.com/android/repository/commandlinetools-linux-12266719_latest.zip -O /tmp/cmdtools.zip \
    && unzip -q /tmp/cmdtools.zip -d "${ANDROID_SDK_ROOT}/cmdline-tools" \
    && mv "${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools" "${ANDROID_SDK_ROOT}/cmdline-tools/latest" \
    && yes | "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null \
    && "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" "build-tools;35.0.0" >/dev/null \
    && rm -rf /tmp/cmdtools.zip /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and checksum helper script
COPY server/ .
COPY scripts/android-signature-checksum.sh scripts/android-signature-checksum.sh
RUN chmod +x scripts/android-signature-checksum.sh

# Set environment variables
ARG SERVER_VERSION=v1.0.1-dev
ENV TIMEKPR_SERVER_VERSION=$SERVER_VERSION
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["gunicorn", "--worker-class", "gevent", "--workers", "1", "--bind", "0.0.0.0:5000", "app:app"]

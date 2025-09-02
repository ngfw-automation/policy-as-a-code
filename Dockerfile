# Use the official Python image from the Docker Hub
FROM python:alpine

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED=True

# Copy local code to the container image.
ENV APP_HOME=/app
WORKDIR $APP_HOME
COPY . ./

# Install core dependencies.
RUN apk add linux-headers wget gcc make zlib-dev libffi-dev openssl-dev musl-dev
RUN apk update && apk upgrade --no-cache sqlite-libs

# Upgrade pip to the latest version
RUN pip install --upgrade pip

# Install any dependencies listed in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# Upgrade pan-python to override the default 0.17.0
RUN pip install pan-python==0.25.0

# Create a group and user called 'nonroot'
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot

USER nonroot

# Run the main Python script when the container starts
CMD ["python", "main.py"]

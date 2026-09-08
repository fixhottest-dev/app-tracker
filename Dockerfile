# RD APK Store V8.3.1 — reproducible Render runtime
# Provides Node.js + Android Build Tools + BSDIFF/BSPATCH.
FROM node:24-bookworm-slim

ENV NODE_ENV=production \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    AAPT_PATH=/opt/android-sdk/build-tools/36.0.0/aapt2 \
    AAPT_FALLBACK_PATH=/opt/android-sdk/build-tools/36.0.0/aapt \
    APKSIGNER_PATH=/opt/android-sdk/build-tools/36.0.0/apksigner \
    BSDIFF_CLI_PATH=/usr/bin/bsdiff \
    BSPATCH_CLI_PATH=/usr/bin/bspatch

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip openjdk-17-jre-headless bsdiff \
    && rm -rf /var/lib/apt/lists/*

# Install Google's official Android command-line tools and Build Tools 36.0.0.
# Build Tools contains aapt, aapt2 and apksigner.
ARG CMDLINE_TOOLS_VERSION=15859902
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools \
    && curl -fsSL --retry 5 --retry-delay 2 \
       "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" \
       -o /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /tmp/android-cmdline \
    && mv /tmp/android-cmdline/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest \
    && rm -rf /tmp/cmdline-tools.zip /tmp/android-cmdline \
    && yes | ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null \
    && ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager "build-tools;36.0.0" \
    && rm -rf ${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/*.bat

ENV PATH="${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/build-tools/36.0.0:${PATH}"

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY index.js ./

# Fail the image build if the required native release toolchain is missing.
RUN node -e "const fs=require('fs'); for (const p of ['/opt/android-sdk/build-tools/36.0.0/aapt2','/opt/android-sdk/build-tools/36.0.0/aapt','/opt/android-sdk/build-tools/36.0.0/apksigner','/usr/bin/bsdiff','/usr/bin/bspatch']) { if (!fs.existsSync(p)) throw new Error('Missing release tool: '+p); } console.log('Release toolchain present.');"
RUN node --check index.js

EXPOSE 10000

CMD ["node", "index.js"]

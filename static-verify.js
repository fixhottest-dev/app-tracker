"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "index.js"), "utf8");
const dockerfile = fs.readFileSync(path.join(root, "Dockerfile"), "utf8");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

function must(condition, message) {
  if (!condition) throw new Error("STATIC VERIFY FAILED: " + message);
  console.log("PASS: " + message);
}

must(pkg.version === "8.3.2", "package version is 8.3.2");
must(source.includes("V8.3.2 ULTIMATE RENDER PRODUCTION EDITION"), "source version is 8.3.2");
must(source.includes('const { MongoStore } = require("connect-mongo");'), "connect-mongo 6 CommonJS named export is used");
must(!source.includes('const MongoStore = require("connect-mongo");'), "legacy connect-mongo import is absent");
must(source.includes("matchedCount"), "Mongo ownership checks use matchedCount semantics");
must(!source.includes('metadataUpdate.modifiedCount !== 1'), "metadata ownership is not inferred from modifiedCount");
must(!source.includes('patchUpdateRes.modifiedCount !== 1'), "patch ownership is not inferred from modifiedCount");
must(!source.includes('apkUpdateRes.modifiedCount !== 1'), "APK ownership is not inferred from modifiedCount");
must(!source.includes('updateResult.modifiedCount !== 1) throw makeOwnershipLostError'), "publication ownership is not inferred from modifiedCount");
must(source.includes('lastErrorCode: { type: String'), "release error code is persisted");
must(source.includes('stage: { type: String'), "release stage is persisted");
must(source.includes("async function ensureReleasePackageLock"), "package lock initialization is centralized");
must(source.includes("await ensureReleasePackageLock(job.extractedPackageName);"), "manual publication uses package lock initialization");
must(source.includes('const packageLock = await ReleasePackageLock.findOneAndUpdate('), "manual publication serializes on package lock");
must(source.includes('let manualPatchTempPath = "";'), "manual patch temp path has function-level scope");
must(source.includes('tempFile === manualPatchTempPath'), "manual patch temp cleanup scope is valid");
must(dockerfile.includes("AAPT_PATH=/opt/android-sdk/build-tools/36.0.0/aapt2"), "Docker pins AAPT2 path");
must(dockerfile.includes("APKSIGNER_PATH=/opt/android-sdk/build-tools/36.0.0/apksigner"), "Docker pins apksigner path");
must(dockerfile.includes("FROM node:24-bookworm-slim"), "Docker uses Node 24 runtime");
must(dockerfile.includes('build-tools;36.0.0'), "Docker installs Android Build Tools 36.0.0");
must(dockerfile.includes("apt-get install -y --no-install-recommends") && dockerfile.includes("bsdiff"), "Docker installs bsdiff/bspatch runtime");
must(dockerfile.includes("USER node"), "container drops root privileges for runtime");
must(dockerfile.includes("node --check index.js"), "Docker performs syntax verification at build time");

console.log("STATIC VERIFY COMPLETE: production hardening checks passed.");

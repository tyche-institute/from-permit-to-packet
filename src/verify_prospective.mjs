#!/usr/bin/env node

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const remote = process.argv.includes("--remote");
const localRoot = new URL("../", import.meta.url);
const remoteRoot = "https://tyche.institute/data/from-permit-to-packet/";
const gates = [];

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256Bytes(Buffer.from(canonical(value), "utf8"));
}

function requireGate(condition, name, detail = "") {
  if (!condition) throw new Error(`${name}${detail ? `: ${detail}` : ""}`);
  gates.push(name);
}

function pathFor(localPath, productionPath) {
  return remote ? productionPath : localPath;
}

async function loadText(path) {
  if (remote) {
    const response = await fetch(new URL(path, remoteRoot), { cache: "no-store" });
    if (!response.ok) throw new Error(`fetch ${path}: HTTP ${response.status}`);
    return response.text();
  }
  return readFile(fileURLToPath(new URL(path, localRoot)), "utf8");
}

async function loadJson(path) {
  return JSON.parse(await loadText(path));
}

function verifyEnvelope(envelope, label) {
  requireGate(envelope.alg === "Ed25519", `${label}.algorithm`);
  const raw = Buffer.from(envelope.public_key_b64, "base64");
  requireGate(raw.length === 32, `${label}.public_key_length`);
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: "der", type: "spki" });
  requireGate(
    verify(null, Buffer.from(canonical(envelope.payload), "utf8"), key, Buffer.from(envelope.signature_b64, "base64")),
    `${label}.signature`,
  );
  if (envelope.public_key_sha256) {
    requireGate(sha256Bytes(raw) === envelope.public_key_sha256, `${label}.public_key_fingerprint`);
  }
}

const [requestText, permit, precommit, creation, closure, witness, captureManifest] = await Promise.all([
  loadText(pathFor("prospective/precommit/api-request.canonical.json", "precommit/api-request.canonical.json")),
  loadJson(pathFor("prospective/precommit/permit.json", "precommit/permit.json")),
  loadJson(pathFor("prospective/precommit/precommit.json", "precommit/precommit.json")),
  loadJson(pathFor("prospective/execution/creation-response.json", "prospective/creation-response.json")),
  loadJson("prospective/closure.json"),
  loadJson(pathFor("prospective/witness/witness.json", "prospective/witness.json")),
  loadJson("prospective/capture-manifest.json"),
]);

const request = JSON.parse(requestText);
const requestDigest = sha256Bytes(Buffer.from(requestText, "utf8"));
verifyEnvelope(permit, "permit");
verifyEnvelope(closure, "closure");
verifyEnvelope(witness, "witness");

requireGate(canonical(precommit.permit) === canonical(permit), "precommit.permit_identity");
requireGate(precommit.state === "PERMITTED_NOT_EXECUTED", "precommit.pre_action_state");
requireGate(Array.isArray(precommit.measurement_ids) && precommit.measurement_ids.length === 0, "precommit.empty_platform_ids");
requireGate(requestDigest === precommit.exact_api_request_sha256, "precommit.request_digest");
requireGate(requestDigest === permit.payload.exact_api_request_sha256, "permit.request_digest");
requireGate(requestDigest === closure.payload.exact_api_request_sha256, "closure.request_digest");
requireGate(digest(permit) === closure.payload.permit_sha256, "closure.permit_digest");
requireGate(digest(creation) === closure.payload.creation_response_sha256, "closure.creation_digest");

const definitions = request.definitions;
const expectedPairs = ["dns/4", "dns/6", "ping/4", "ping/6", "sslcert/4", "sslcert/6", "traceroute/4", "traceroute/6"];
const observedPairs = definitions.map((item) => `${item.type}/${item.af}`).sort();
requireGate(definitions.length === 8 && canonical(observedPairs) === canonical(expectedPairs), "action.definition_set");
requireGate(definitions.every((item) => (item.type === "dns" ? item.query_argument : item.target) === "tyche.institute"), "action.target");
requireGate(definitions.every((item) => item.is_public === true && item.auto_topup === false), "action.public_no_topup");
requireGate(request.is_oneoff === true, "action.oneoff");
requireGate(canonical(request.probes) === canonical([{ type: "probes", value: "28,81,6349,6569", requested: 4 }]), "action.explicit_sources");
requireGate(permit.payload.allowed_execution_hosts.length === 1 && permit.payload.allowed_execution_hosts[0] === "zeus1", "permit.execution_host");
requireGate(permit.payload.maximum_credits === 1060, "permit.credit_ceiling");

const ids = closure.payload.measurement_ids;
requireGate(ids.length === 8 && new Set(ids).size === 8, "effect.platform_id_shape");
requireGate(canonical(ids) === canonical(creation.measurements), "effect.creation_ids");
requireGate(canonical(ids) === canonical(witness.payload.measurement_ids), "witness.measurement_ids");
requireGate(canonical(closure.payload.witness) === canonical(witness), "closure.witness_identity");
requireGate(witness.payload.agrees_with_collector === true, "witness.collector_agreement");

const sourceIndex = closure.payload.source_index;
const resultCount = sourceIndex.reduce((sum, item) => sum + item.result_count, 0);
const successCount = sourceIndex.reduce((sum, item) => sum + item.narrow_success_count, 0);
const creditCount = sourceIndex.reduce((sum, item) => sum + item.credits_observed, 0);
const allowedSources = new Set([28, 81, 6349, 6569]);
requireGate(sourceIndex.length === 8, "evidence.source_index_shape");
requireGate(sourceIndex.every((item) => item.complete_scheduled_source_coverage === true), "evidence.complete_source_coverage");
requireGate(sourceIndex.every((item) => item.returned_probe_ids.every((id) => allowedSources.has(id))), "evidence.source_scope");
requireGate(resultCount === closure.payload.claim.result_count && resultCount === witness.payload.result_count, "claim.result_count");
requireGate(successCount === closure.payload.claim.narrow_success_count && successCount === witness.payload.narrow_success_count, "claim.success_count");
requireGate(creditCount === closure.payload.claim.credits_observed_from_result_count && creditCount <= permit.payload.maximum_credits, "claim.credit_count");
requireGate(closure.payload.claim.kind === "bounded_observation", "claim.class");
requireGate(closure.payload.verifier.verdict === "ALLOW" && closure.payload.verifier.first_bad_edge === null, "closure.verdict");

for (const item of sourceIndex) {
  const metadata = captureManifest.files[`measurements/${item.measurement_id}.json`];
  const results = captureManifest.files[`results/${item.measurement_id}.json`];
  requireGate(metadata?.sha256 === item.metadata_sha256, `manifest.metadata.${item.measurement_id}`);
  requireGate(results?.sha256 === item.results_sha256, `manifest.results.${item.measurement_id}`);
}

const output = {
  schema: "tyche-permit-to-packet-external-verifier-v0.1",
  verdict: "PASS",
  source_mode: remote ? "public-production" : "checked-out-release-artifacts",
  execution_boundary: process.env.GITHUB_ACTIONS === "true"
    ? "GitHub-hosted runner: separate from zeus1, but under the same repository administration and not an independent auditor"
    : "local verifier execution",
  verified_gate_count: gates.length,
  request_sha256: requestDigest,
  measurement_ids: ids,
  result_count: resultCount,
  narrow_success_count: successCount,
  observed_credits: creditCount,
};

process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);

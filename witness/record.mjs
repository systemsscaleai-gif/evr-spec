// The outside witness recorder for North Star Verified receipts.
//
// It runs on a schedule in a PUBLIC repository that the North Star site does
// not control at run time (see witness/README.md). Each run reads public
// addresses on the site and appends one line to witness/log.jsonl:
//
//   - the fingerprint of the newest seal in the chain,
//   - the fingerprints of receipts on the public register that the log has not
//     listed before,
//   - the fingerprints of corrections on those receipts that the log has not
//     listed before ("corrections"), and
//   - the fingerprints of AI register versions sent to North Star for a date
//     that the log has not listed before ("registers"). A fingerprint reveals
//     nothing of what a register says.
//
// It also keeps a copy of the published signing keys in witness/receipt-keys.json.
// Fingerprints, receipt IDs and public keys only. Nothing private can reach
// this file, because the site's public addresses never serve it.
//
// Node 20 or newer. No dependencies.

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";

export const LOG_VERSION = 1;
// One run reads the whole public register, a page at a time. The site names the
// next page. A register too long for this many pages stops the run with an
// error instead of logging part of it: raise the number (the site allows 120
// reads an hour from one address).
export const MAX_PAGES = 40;
// The dated AI register feed pages 1,000 fingerprints at a time (the site
// allows 120 reads an hour from one address).
export const MAX_REGISTER_PAGES = 40;
export const REGISTER_STANDARD = "North Star AI Register dates";
const SHA256 = /^[0-9a-f]{64}$/;
const SEAL_ID = /^NSV-\d{4}-[0-9A-HJKMNP-TV-Z]{6}$/;
const CORRECTION_ID = /^NSV-\d{4}-[0-9A-HJKMNP-TV-Z]{6}\/C[1-9]\d{0,3}$/;

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);

/** The receipt IDs the log already lists. Lines that do not parse are ignored. */
export function loggedReceiptIds(logText) {
  const ids = new Set();
  for (const line of logText.split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      for (const receipt of Array.isArray(entry?.published) ? entry.published : []) if (typeof receipt?.id === "string") ids.add(receipt.id);
    } catch { /* a damaged line never stops the recorder */ }
  }
  return ids;
}

/**
 * The corrections the log already lists, as "<id> <fingerprint>". The fingerprint is part of
 * the key on purpose: if the site ever serves a different fingerprint for a place the log
 * already holds, the new one is logged too, and the two lines are the evidence of a rewrite.
 */
export function loggedCorrections(logText) {
  const seen = new Set();
  for (const line of logText.split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      for (const correction of Array.isArray(entry?.corrections) ? entry.corrections : []) {
        if (typeof correction?.id === "string" && typeof correction?.payload_sha256 === "string") seen.add(`${correction.id} ${correction.payload_sha256}`);
      }
    } catch { /* a damaged line never stops the recorder */ }
  }
  return seen;
}

/** The AI register fingerprints the log already lists. Lines that do not parse are ignored. */
export function loggedRegisterFingerprints(logText) {
  const seen = new Set();
  for (const line of logText.split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      for (const fingerprint of Array.isArray(entry?.registers) ? entry.registers : []) if (typeof fingerprint === "string") seen.add(fingerprint);
    } catch { /* a damaged line never stops the recorder */ }
  }
  return seen;
}

/** One page of the dated AI register feed, or an Error. Only fingerprints are kept: the site's own dates are not the witness's. */
export function readRegisterPage(body) {
  if (!isRecord(body) || body.standard !== REGISTER_STANDARD) throw new Error("the register dates answer is not a North Star AI Register dates answer");
  if (!Array.isArray(body.fingerprints)) throw new Error("the register dates page is missing");
  const next = body.next_offset;
  if (next !== null && !(Number.isInteger(next) && next > 0 && next <= 100_000_000)) throw new Error("the next register dates page is not named");
  const fingerprints = body.fingerprints.map((item) => {
    if (!isRecord(item) || typeof item.sha256 !== "string" || !SHA256.test(item.sha256)) throw new Error("a register fingerprint is malformed");
    return item.sha256;
  });
  return { fingerprints, next_offset: next };
}

/** One page of the chain endpoint, or an Error naming what was wrong with it. Nothing malformed is ever logged. */
export function readChainPage(body) {
  if (!isRecord(body) || body.standard !== "North Star Verified") throw new Error("the chain answer is not a North Star Verified answer");
  const head = body.head_sha256 ?? null;
  if (head !== null && !(typeof head === "string" && SHA256.test(head))) throw new Error("the newest seal fingerprint is malformed");
  if (!Array.isArray(body.published)) throw new Error("the register page is missing");
  const next = body.next_offset;
  if (next !== null && !(Number.isInteger(next) && next > 0 && next <= 100000)) throw new Error("the next page is not named");
  const published = body.published.map((receipt) => {
    if (!isRecord(receipt) || typeof receipt.id !== "string" || !SEAL_ID.test(receipt.id) || typeof receipt.payload_sha256 !== "string" || !SHA256.test(receipt.payload_sha256)) {
      throw new Error("a register receipt is malformed");
    }
    return { id: receipt.id, payload_sha256: receipt.payload_sha256 };
  });
  // No field means the site could not read its corrections this time (or predates them): "not read".
  let corrections = null;
  if (body.corrections !== undefined) {
    if (!Array.isArray(body.corrections)) throw new Error("the corrections list is malformed");
    corrections = body.corrections.map((correction) => {
      if (!isRecord(correction) || typeof correction.id !== "string" || !CORRECTION_ID.test(correction.id) || typeof correction.payload_sha256 !== "string" || !SHA256.test(correction.payload_sha256)) {
        throw new Error("a correction is malformed");
      }
      return { id: correction.id, payload_sha256: correction.payload_sha256 };
    });
  }
  return { head_sha256: head, published, corrections, next_offset: next };
}

/** Sorted-key JSON, so the same key list always has the same fingerprint. */
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

export const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");

/** The published keys as the site lists them, or an Error. */
export function readKeys(body) {
  if (!isRecord(body) || !Array.isArray(body.keys) || !body.keys.length) throw new Error("the key list is missing or empty");
  return body.keys.map((key) => {
    if (!isRecord(key) || typeof key.key_id !== "string" || typeof key.public_key !== "string") throw new Error("a published key is malformed");
    return { key_id: key.key_id, public_key: key.public_key, algorithm: typeof key.algorithm === "string" ? key.algorithm : null, created_at: typeof key.created_at === "string" ? key.created_at : null, retired_at: typeof key.retired_at === "string" ? key.retired_at : null };
  });
}

/**
 * The line this run appends. `observedAt` is the recorder's own clock, never a
 * time the site supplied: the recorder is the witness.
 *
 * `registerPages` is null when the dated register feed could not be read: the
 * line then carries no "registers" field at all, so a reader can tell "not
 * read this run" (no field) from "read, nothing new" (an empty list).
 *
 * "corrections" follows the same rule: the field is written only when every
 * page of the register carried its corrections list.
 */
export function nextEntry({ logText, pages, keys, observedAt, source, registerPages = null }) {
  const known = loggedReceiptIds(logText);
  const fresh = [];
  for (const page of pages) {
    for (const receipt of page.published) {
      if (known.has(receipt.id)) continue;
      known.add(receipt.id);
      fresh.push(receipt);
    }
  }
  const entry = { v: LOG_VERSION, observed_at: observedAt, source, head_sha256: pages[0]?.head_sha256 ?? null, published: fresh };
  if (pages.length && pages.every((page) => Array.isArray(page.corrections))) {
    const seen = loggedCorrections(logText);
    const corrections = [];
    for (const page of pages) {
      for (const correction of page.corrections) {
        const key = `${correction.id} ${correction.payload_sha256}`;
        if (seen.has(key)) continue;
        seen.add(key);
        corrections.push(correction);
      }
    }
    entry.corrections = corrections;
  }
  if (registerPages !== null) {
    const seen = loggedRegisterFingerprints(logText);
    const registers = [];
    for (const page of registerPages) {
      for (const fingerprint of page.fingerprints) {
        if (seen.has(fingerprint)) continue;
        seen.add(fingerprint);
        registers.push(fingerprint);
      }
    }
    entry.registers = registers;
  }
  entry.keys_sha256 = sha256(canonical(keys));
  return entry;
}

async function getJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(20_000) });
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  return response.json();
}

/**
 * Reads the whole public register, following the next page the site names.
 *
 * Every run reads every page. A receipt can join the register long after it was
 * sealed, anywhere in the order, so stopping at the first page with nothing new
 * would miss it for good.
 */
export async function readPages(source, get = getJson) {
  const pages = [];
  let offset = 0;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const read = readChainPage(await get(`${source}/api/public/receipt-chain?offset=${offset}`));
    pages.push(read);
    if (read.next_offset === null) return pages;
    if (read.next_offset <= offset) throw new Error("the register pages do not move forward");
    offset = read.next_offset;
  }
  throw new Error(`the public register is longer than ${MAX_PAGES} pages: raise MAX_PAGES in witness/record.mjs`);
}

/** Reads the whole dated AI register feed, oldest first, following the next page the site names. */
export async function readRegisterPages(source, get = getJson) {
  const pages = [];
  let offset = 0;
  for (let page = 0; page < MAX_REGISTER_PAGES; page += 1) {
    const read = readRegisterPage(await get(`${source}/api/public/ai-register-dates?offset=${offset}`));
    pages.push(read);
    if (read.next_offset === null) return pages;
    if (read.next_offset <= offset) throw new Error("the register dates pages do not move forward");
    offset = read.next_offset;
  }
  throw new Error(`the dated register feed is longer than ${MAX_REGISTER_PAGES} pages: raise MAX_REGISTER_PAGES in witness/record.mjs`);
}

export async function run({ source = "https://northstarintel.ai", logPath = "witness/log.jsonl", keysPath = "witness/receipt-keys.json", now = () => new Date(), get = getJson, warn = (message) => console.warn(message) } = {}) {
  const logText = await readFile(logPath, "utf8").catch(() => "");
  const pages = await readPages(source, get);
  const keys = readKeys(await get(`${source}/api/public/receipt-keys`));
  // The receipts line never waits on the register feed: a feed that cannot be
  // read leaves "registers" off this line, and the site's health watch reports
  // a dated version the log has not listed in time.
  let registerPages = null;
  try {
    registerPages = await readRegisterPages(source, get);
  } catch (error) {
    warn(`register dates not read: ${error instanceof Error ? error.message : error}`);
  }
  const entry = nextEntry({ logText, pages, keys, observedAt: now().toISOString(), source, registerPages });
  await mkdir(dirname(logPath), { recursive: true });
  await writeFile(logPath, `${logText}${logText && !logText.endsWith("\n") ? "\n" : ""}${JSON.stringify(entry)}\n`, "utf8");
  await writeFile(keysPath, `${JSON.stringify({ standard: "North Star Verified", source: `${source}/api/public/receipt-keys`, keys }, null, 2)}\n`, "utf8");
  return entry;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run({ source: process.env.WITNESS_SOURCE || undefined }).then(
    (entry) => console.log(`recorded: newest seal ${entry.head_sha256 ?? "none"}, ${entry.published.length} new public receipt(s), ${entry.corrections ? `${entry.corrections.length} new correction(s)` : "corrections not read"}, ${entry.registers ? `${entry.registers.length} new register fingerprint(s)` : "register dates not read"}`),
    (error) => { console.error(`not recorded: ${error instanceof Error ? error.message : error}`); process.exit(1); },
  );
}

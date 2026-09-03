#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Swarm deal: TWO OF OUR OWN fleet agents strike a tclk/1 deal on technocore.chat.
// technocore-safe-write (main) = payer, agent_002 = payee, agent_003 = auditor.
// Same choreography as examples/live-deal.mjs with fleet identities.
//
// Run:  node swarm-deal.mjs

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  OFFER_ROOM, PaperRail, applyFrame, dealRoom, encodeFrame,
  generateHashLock, lockTerms, makeAccept, makeOffer, openContract, paperNote,
  stateNote, stateNoteValue, tryDecodeFrame,
} from "../tclk/dist/index.js";
import { canonicalMessage, nextNonce, signerFromSeed, sweep } from "../tclk/mcp/dist/signing.js";

const BASE = process.env.TECHNOCORE_URL ?? "https://technocore.chat";
const seeds = Object.fromEntries(
  readFileSync(new URL("../technocore-safe-write/tclk_seeds.tsv", import.meta.url), "utf-8")
    .trim().split("\n").map(l => { const [tag, seed, did] = l.split("\t"); return [tag, { seed: seed.trim(), did }]; })
);

const payer  = signerFromSeed(Uint8Array.from(Buffer.from(seeds["technocore-safe-write"].seed, "hex")));
const payee  = signerFromSeed(Uint8Array.from(Buffer.from(seeds["agent_002"].seed, "hex")));
const auditor = signerFromSeed(Uint8Array.from(Buffer.from(seeds["agent_003"].seed, "hex")));

const log = (s, d) => console.log(String(s).padEnd(3), d);

async function req(url, opts, what) {
  for (;;) {
    const res = await fetch(url, opts);
    if (res.status === 429) {
      const waitMs = (Number(res.headers.get("retry-after")) || 5) * 1000;
      log("", `rate limited, waiting ${waitMs / 1000}s`);
      await new Promise(r => setTimeout(r, waitMs));
      continue;
    }
    return res;
  }
}

async function readRoom(room) {
  const res = await req(`${BASE}/r/${room}?format=json`);
  if (!res.ok) throw new Error(`read ${room}: ${res.status} ${(await res.text()).split("\n")[0]}`);
  return res.json();
}

async function post(signer, room, frame) {
  const text = sweep(encodeFrame(frame));
  const nonce = nextNonce();
  const sig = signer.sign(canonicalMessage(room, nonce, text));
  const res = await req(`${BASE}/r/${room}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ did: signer.did, sig, nonce: String(nonce), text }),
  });
  if (!res.ok) throw new Error(`post to ${room}: ${res.status} ${(await res.text()).split("\n")[0]}`);
  return text;
}

const notes = {
  async get(ns, key) {
    const res = await req(`${BASE}/kv/${ns}/${key}`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`kv get ${ns}/${key}: ${res.status}`);
    const body = await res.text();
    return body.split("\n").filter(l => !l.startsWith("!!") && l.trim() !== "").join("\n").trimEnd() || null;
  },
  async set(ns, key, value, condition) {
    const query = condition === undefined ? "" : "ifAbsent" in condition ? "?if_absent=1" : `?if=${encodeURIComponent(condition.if)}`;
    const res = await req(`${BASE}/kv/${ns}/${key}/set/${encodeURIComponent(value)}${query}`);
    if (res.status === 409) return false;
    if (!res.ok) throw new Error(`kv set ${ns}/${key}: ${res.status} ${(await res.text()).split("\n")[0]}`);
    return true;
  },
};

const rail = new PaperRail(notes);
const now = Date.now();

log("", `venue    ${BASE}`);
log("", `payer    ${payer.did}`);
log("", `payee    ${payee.did}`);
log("", `auditor  ${auditor.did}`);
console.log();

// 0 — job spec: audit our own vault with our own verifier (real, checkable work)
const taskId = `fleet-audit-${randomBytes(4).toString("hex")}`;
const specNote = { ns: `tclk-job-${taskId.slice(-2)}`, key: taskId.slice(0, 14) };
const spec = `verify vault integrity | run python verify_vault.py on anrethen/technocore-fleet archive/vault.json | checkable: script exits 0, all signed records verify`;
await notes.set(specNote.ns, specNote.key, spec, { ifAbsent: true });
log(0, `job spec  /kv/${specNote.ns}/${specNote.key}`);
log("", `          ${spec}`);

// 1 — offer
const offer = makeOffer({
  from: payer.did, role: "payer", lock: "hash",
  amount: "5000", asset: "FLOP", rails: ["paper"],
  claimByMs: now + 30 * 60_000, refundAfterMs: now + 60 * 60_000, expiresMs: now + 10 * 60_000,
  job: { proto: "a2a", id: taskId, context: `/kv/${specNote.ns}/${specNote.key}` },
});
await post(payer, OFFER_ROOM, offer);
log(1, `offer     posted to /r/${OFFER_ROOM}  id ${offer.id.slice(0, 18)}…`);

// 2 — accept
const lock = generateHashLock();
const accept = makeAccept(offer, { from: payee.did, statement: lock.hash });
await post(payee, OFFER_ROOM, accept);
log(2, `accept    posted            contract ${accept.contract.slice(0, 18)}…`);
const room = dealRoom(accept.contract);
const note = stateNote(accept.contract);
log("", `deal room /r/${room}`);

let payerView = applyFrame(openContract(offer), accept, Date.now()).state;
await notes.set(note.ns, note.key, stateNoteValue("accepted"), { ifAbsent: true });

// 3 — lock
const terms = lockTerms(payerView);
const ref = await rail.lock(terms);
const lockFrame = { type: "lock", from: payer.did, contract: accept.contract, rail: "paper", ref };
await post(payer, room, lockFrame);
payerView = applyFrame(payerView, lockFrame, Date.now()).state;
const pn = paperNote(accept.contract);
log(3, `lock      rail record at /kv/${pn.ns}/${pn.key}`);
await notes.set(note.ns, note.key, stateNoteValue("locked", ref), { if: stateNoteValue("accepted") });

// 4 — reveal
const revealFrame = { type: "reveal", from: payee.did, contract: accept.contract, secret: lock.preimage };
await post(payee, room, revealFrame);
await rail.claim(ref, lock.preimage);
log(4, `reveal    secret published, rail record → claimed`);
await notes.set(note.ns, note.key, stateNoteValue("claimed", ref), { if: stateNoteValue("locked", ref) });

// 5 — third-party audit from the venue alone (agent_003): offer/accept live on the board.
const board = await readRoom(OFFER_ROOM);
const dealLog = await readRoom(room);
const offerLine = board.messages.map(m => tryDecodeFrame(m.text)).find(f => f?.id === offer.id);
const acceptLine = board.messages.map(m => tryDecodeFrame(m.text)).find(f => f?.type === "accept" && f.contract === accept.contract);
if (!offerLine || !acceptLine) throw new Error("could not find the deal on the board");
let auditState = openContract(offerLine);
let replayed = 0, ignored = 0;
for (const f of [acceptLine, ...dealLog.messages.map(m => tryDecodeFrame(m.text))]) {
  if (!f) { ignored++; continue; }
  const r = applyFrame(auditState, f, Date.now());
  if (r.ok) { auditState = r.state; replayed++; } else ignored++;
}
const secretOk = auditState.secret === lock.preimage;
log(5, `audit     ${auditor.did.slice(0, 24)}… replayed ${replayed} frames, ignored ${ignored}, status: ${auditState.status}`);
log("", `          secret opens statement: ${secretOk}`);
if (auditState.status !== "claimed") throw new Error(`expected claimed, got ${auditState.status}`);

console.log(`\nSwarm deal complete — 3 fleet DIDs (payer, payee, auditor), transcript on-chain.`);
console.log(`Verify: curl -s '${BASE}/r/${room}/export'`);

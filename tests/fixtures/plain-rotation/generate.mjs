// Generates a didwebvh-ts log that exercises plain key rotation
// (no pre-rotation / no nextKeyHashes). Produced log is the regression
// fixture for issue #35 — didwebvh-rs rejected such logs because its
// no-pre-rotation auth branch checked the proof against the current
// entry's updateKeys instead of the previous entry's.
//
// Usage: node generate.mjs > ../../test_vectors/plain_rotation.jsonl
//
// Re-run from this directory; commit the resulting jsonl. The Node
// pipeline is not part of CI — fixtures are static once generated.

import { createDID, updateDID, AbstractCrypto } from "didwebvh-ts";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512.js";
import { writeFileSync } from "node:fs";

ed.hashes.sha512 = (msg) => sha512(msg);

// Multibase base58btc with 0xed01 multicodec prefix (Ed25519 public key).
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = "";
  for (let i = 0; i < zeros; i++) str += BASE58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) str += BASE58_ALPHABET[digits[i]];
  return str;
}

function publicKeyMultibase(pub32) {
  const prefixed = new Uint8Array(2 + pub32.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub32, 2);
  return "z" + base58Encode(prefixed);
}

class Ed25519Signer extends AbstractCrypto {
  constructor(privKey, pubKey, mb) {
    // useStaticId=true (default) derives the VM id as did:key:{mb}#{mb}
    super({ verificationMethod: { type: "Multikey", publicKeyMultibase: mb } });
    this.priv = privKey;
    this.pub = pubKey;
  }
  async sign({ document, proof }) {
    const { prepareDataForSigning } = await import("didwebvh-ts");
    const data = await prepareDataForSigning(document, proof);
    const sig = await ed.signAsync(data, this.priv);
    // base58btc multibase of raw signature bytes.
    return { proofValue: "z" + base58Encode(sig) };
  }
  async verify(signature, message, publicKey) {
    return ed.verifyAsync(signature, message, publicKey);
  }
}

async function makeKey() {
  const priv = ed.utils.randomSecretKey();
  const pub = await ed.getPublicKeyAsync(priv);
  const mb = publicKeyMultibase(pub);
  return { priv, pub, mb, didKey: `did:key:${mb}#${mb}` };
}

const k1 = await makeKey();
const k2 = await makeKey();
const k3 = await makeKey();

const signer1 = new Ed25519Signer(k1.priv, k1.pub, k1.mb);

const created = await createDID({
  domain: "example.com",
  signer: signer1,
  verifier: signer1,
  updateKeys: [k1.mb],
  verificationMethods: [
    { type: "Multikey", publicKeyMultibase: k1.mb, purpose: "assertionMethod" },
  ],
  // Note: no nextKeyHashes — plain rotation, the case issue #35 exercises.
});

const signer2 = new Ed25519Signer(k2.priv, k2.pub, k2.mb);

// Update 1: rotate K1 -> K2. Signed by K1 (still in updateKeys at the time
// the signature is taken — that's the spec's no-pre-rotation rule).
const update1 = await updateDID({
  log: created.log,
  signer: signer1,
  verifier: signer1,
  updateKeys: [k2.mb],
  verificationMethods: [
    { type: "Multikey", publicKeyMultibase: k2.mb, purpose: "assertionMethod" },
  ],
});

// Update 2: rotate K2 -> K3. Signed by K2.
const update2 = await updateDID({
  log: update1.log,
  signer: signer2,
  verifier: signer2,
  updateKeys: [k3.mb],
  verificationMethods: [
    { type: "Multikey", publicKeyMultibase: k3.mb, purpose: "assertionMethod" },
  ],
});

const out = update2.log.map((entry) => JSON.stringify(entry)).join("\n") + "\n";

const target =
  process.argv[2] ?? "../../test_vectors/plain_rotation_no_prerotation.jsonl";
writeFileSync(target, out);

console.error(`Wrote ${update2.log.length} entries to ${target}`);
console.error(`DID: ${update2.did}`);

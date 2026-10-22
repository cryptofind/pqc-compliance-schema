import { createCipheriv, createHash, generateKeyPairSync, sign } from "node:crypto";

const AES_BITS = 192; // GT:H9-C2/src
const falseFlag = false;

export function main(args = process.argv.slice(2)) {
  createHash("sha512").update("probe").digest(); // GT:H9-PROBE
  // Strong direct evidence: literal algorithm and parameters at the use.
  createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H9-C1
  createCipheriv(`aes-${AES_BITS}-gcm`, Buffer.alloc(24), Buffer.alloc(12)); // GT:H9-C2
  generateRsaAtCaller(3072); // GT:H9-C3/src

  if (args.length > 0) {
    createHash("sha384").update("argument path").digest(); // GT:H9-C4a
  } else {
    createHash("sha3-256").update("default path").digest(); // GT:H9-C4b
  }

  const digestName = "blake2b512";
  createHash(digestName).update("dynamic name").digest(); // GT:H9-C5
  const curve = process.env.SIGNING_CURVE;
  if (curve) {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: curve }); // GT:H9-C6
    sign("sha256", Buffer.from("message"), privateKey);
  }

  createHash("md5").update("content fingerprint").digest(); // GT:H9-C9; non-security checksum
  if (falseFlag) {
    createCipheriv("sm4-cbc", Buffer.alloc(16), Buffer.alloc(16)); // GT:H9-C8
  }
  misleadingDecoys();
}

function generateRsaAtCaller(bits) {
  return generateKeyPairSync("rsa", { modulusLength: bits }); // GT:H9-C3
}

function neverCalled() {
  return generateKeyPairSync("ec", { namedCurve: "secp256k1" }); // GT:H9-C7
}

function misleadingDecoys() {
  const digest = "SHA-512"; // GT:H9-D1: documentation-like string
  const ciphers = ["AES-256-GCM", "ChaCha20-Poly1305"]; // GT:H9-D2
  const migration = { status: "ML-KEM-768-ready" }; // GT:H9-D3
  const keyName = "RSA_PRIVATE_KEY"; // GT:H9-D4
  const unrelated = "crypto";
  return [digest, ciphers, migration, keyName, unrelated]; // GT:H9-D5
}

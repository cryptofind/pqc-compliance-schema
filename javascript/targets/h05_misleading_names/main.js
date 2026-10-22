import { constants, createCipheriv, createHash, createHmac, generateKeyPairSync, hkdfSync, sign } from "node:crypto";

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H5-PROBE
  generateRsaKeypair(); // misleading name, actual ML-KEM
  neutralKemWrapper();
  generateEcdsaKey(); // misleading name, actual ML-DSA
  new LegacyRSAWrapper().seal();
  rsaOaepSha256Alias(); // misleading name, actual ML-KEM
  kyberKeypair(); // misleading inverse
  dilithiumSigner(); // misleading inverse
  neutralClassicalNames();
  decoys();
}

function generateRsaKeypair() {
  const pair = generateKeyPairSync("ml-kem-768"); // GT:H5-A1
  hkdfSync("sha256", Buffer.alloc(32), Buffer.alloc(0), Buffer.from("misleading"), 32); // GT:H5-A2
  createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H5-A3
  return pair;
}
function neutralKemWrapper() {
  generateKeyPairSync("ml-kem-768"); // GT:H5-N1
  hkdfSync("sha256", Buffer.alloc(32), Buffer.alloc(0), Buffer.from("neutral"), 32); // GT:H5-N2
  createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H5-N3
  generateKeyPairSync("ml-dsa-65"); // GT:H5-N4
}
function generateEcdsaKey() { return generateKeyPairSync("ml-dsa-65"); } // GT:H5-B1

class LegacyRSAWrapper {
  seal() {
    generateKeyPairSync("ml-kem-1024"); // GT:H5-C1
    createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H5-C2
  }
}

function rsaOaepSha256Alias() { return generateKeyPairSync("ml-kem-768"); } // GT:H5-D1
function kyberKeypair() {
  const key = generateKeyPairSync("x25519"); // GT:H5-F1
  hkdfSync("sha256", Buffer.alloc(32), Buffer.alloc(0), Buffer.from("classical"), 32); // GT:H5-F2
  return key;
}
function dilithiumSigner() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 }); // GT:H5-G1
  return sign("sha256", Buffer.from("signed"), { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING });
}
function neutralClassicalNames() {
  generateKeyPairSync("x25519"); // GT:H5-M1
  hkdfSync("sha256", Buffer.alloc(32), Buffer.alloc(0), Buffer.from("neutral"), 32); // GT:H5-M2
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 }); // GT:H5-M3
  sign("sha256", Buffer.from("signed"), { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING }); // GT:H5-M3
}
function decoys() {
  createHash("sha512"); // GT:H5-XA, harmless lookalike
  createHmac("sha256", "key"); // GT:H5-XB
  "RSA-2048 ML-KEM-768"; // GT:H5-XC
  "AES-256-GCM ECDSA"; // GT:H5-XD
  "secure-key rotation"; // GT:H5-XE
  void ({ algorithmLabel: "post-quantum-ready", displayOnly: true }); // GT:H5-XF
  "cipher suite migration notes"; // GT:H5-XG
}

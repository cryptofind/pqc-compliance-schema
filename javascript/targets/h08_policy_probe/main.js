import { createCipheriv, createHash, createHmac, generateKeyPairSync, hkdfSync, publicEncrypt, constants, sign } from "node:crypto";

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H8-PROBE
  // Individual policy-discriminating units.
  createCipheriv("aes-128-gcm", Buffer.alloc(16), Buffer.alloc(12)); // GT:H8-P01
  createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H8-P02
  createCipheriv("chacha20-poly1305", Buffer.alloc(32), Buffer.alloc(12)); // GT:H8-P03
  createHash("sha256").update("x").digest(); // GT:H8-P04
  createHash("sha384").update("x").digest(); // GT:H8-P05
  createHash("sha3-256").update("x").digest(); // GT:H8-P06
  createHash("sha1").update("x").digest(); // GT:H8-P07
  createHash("sha224").update("x").digest(); // GT:H8-P08
  createHmac("sha256", "key").update("x").digest(); // GT:H8-P09
  createHmac("sha384", "key").update("x").digest(); // GT:H8-P10
  generateKeyPairSync("ml-kem-512"); // GT:H8-P11
  generateKeyPairSync("ml-kem-768"); // GT:H8-P12
  generateKeyPairSync("ml-kem-1024"); // GT:H8-P13
  generateKeyPairSync("ml-dsa-44"); // GT:H8-P14
  generateKeyPairSync("ml-dsa-87"); // GT:H8-P15
  generateKeyPairSync("slh-dsa-sha2-128s"); // GT:H8-P16
  const { privateKey: rsaSigningKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  sign("sha256", Buffer.from("x"), { key: rsaSigningKey, padding: constants.RSA_PKCS1_PSS_PADDING }); // GT:H8-P17
  publicEncrypt({ key: "rsa-key", padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from("x")); // GT:H8-P18
  const { privateKey: ecSigningKey } = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  sign("sha384", Buffer.from("x"), ecSigningKey); // GT:H8-P19
  generateKeyPairSync("ed25519"); // GT:H8-P20
  generateKeyPairSync("x25519"); // GT:H8-P21
  hybridKex(); // GT:H8-P22
  cnsaHybrid(); // GT:H8-P23
}

function hybridKex() {
  generateKeyPairSync("x25519"); // GT:H8-P22-C
  generateKeyPairSync("ml-kem-768"); // GT:H8-P22-Q
  hkdfSync("sha256", Buffer.alloc(32), Buffer.alloc(0), Buffer.from("hybrid"), 32); // GT:H8-P22-K
}

function cnsaHybrid() {
  generateKeyPairSync("ec", { namedCurve: "secp384r1" }); // GT:H8-P23-C
  generateKeyPairSync("ml-kem-1024"); // GT:H8-P23-Q
  hkdfSync("sha384", Buffer.alloc(32), Buffer.alloc(0), Buffer.from("hybrid"), 32); // GT:H8-P23-K
}

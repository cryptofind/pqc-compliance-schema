import { constants, createCipheriv, createHash, diffieHellman, encapsulate, generateKeyPairSync, hkdfSync, publicEncrypt, sign, verify } from "node:crypto";

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H4-PROBE
  hybridExchange();
  compositeSignature();
  authenticatedKeyExchange();
  rsaEnvelope();
  downgradeFallback();
  allPqc();
  cnsaHybrid();
}

function hybridExchange() {
  const classical = generateKeyPairSync("x25519"); // GT:H4-U1-C
  const kem = generateKeyPairSync("ml-kem-768"); // GT:H4-U1-Q
  const classicalSecret = diffieHellman({ privateKey: classical.privateKey, publicKey: classical.publicKey });
  const { sharedKey, ciphertext } = encapsulate(kem.publicKey);
  return { ciphertext, secret: hkdfSync("sha256", Buffer.concat([classicalSecret, sharedKey]), Buffer.alloc(0), Buffer.from("hybrid"), 32) }; // GT:H4-U1-K
}

function compositeSignature() {
  const pq = generateKeyPairSync("ml-dsa-65"); // GT:H4-U2-Q
  const classical = generateKeyPairSync("ed25519"); // GT:H4-U2-C
  const message = Buffer.from("message");
  const signatures = [sign("sha512", message, pq.privateKey), sign(null, message, classical.privateKey)];
  return signatures.every((signature, index) => verify(
    index === 0 ? "sha512" : null,
    message,
    index === 0 ? pq.publicKey : classical.publicKey,
    signature,
  ));
}

function authenticatedKeyExchange() {
  const kem = generateKeyPairSync("ml-kem-768"); // GT:H4-U3-Q
  const authentication = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); // GT:H4-U3-A
  const transcript = Buffer.from("authenticated key exchange");
  const signature = sign("sha256", transcript, authentication.privateKey);
  const { sharedKey } = encapsulate(kem.publicKey);
  return { signature, secret: hkdfSync("sha256", sharedKey, Buffer.alloc(0), transcript, 32) }; // GT:H4-U3-K
}

function rsaEnvelope() {
  publicEncrypt({ key: "rsa-key", padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from("data")); // GT:H4-U4-C
  createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H4-U4-S
}

function downgradeFallback() {
  const kem = generateKeyPairSync("ml-kem-1024"); // GT:H4-U5-Q
  try {
    const { sharedKey } = encapsulate(kem.publicKey);
    return hkdfSync("sha384", sharedKey, Buffer.alloc(0), Buffer.from("hybrid"), 32); // GT:H4-U5-K
  } catch {
    const classicalSecret = publicEncrypt({ key: "rsa-key", padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from("fallback")); // GT:H4-U5-C
    return hkdfSync("sha384", classicalSecret, Buffer.alloc(0), Buffer.from("fallback"), 32); // GT:H4-U5-K
  } finally {
    createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12)); // GT:H4-U5-S
  }
}

function allPqc() {
  const kem = generateKeyPairSync("ml-kem-1024"); // GT:H4-U6-Q
  const { sharedKey } = encapsulate(kem.publicKey);
  const key = hkdfSync("sha384", sharedKey, Buffer.alloc(0), Buffer.from("pqc"), 32); // GT:H4-U6-K
  return createCipheriv("aes-256-gcm", key, Buffer.alloc(12)); // GT:H4-U6-S
}

function cnsaHybrid() {
  const classical = generateKeyPairSync("ec", { namedCurve: "secp384r1" }); // GT:H4-U7-C
  const kem = generateKeyPairSync("ml-kem-1024"); // GT:H4-U7-Q
  const classicalSecret = diffieHellman({ privateKey: classical.privateKey, publicKey: classical.publicKey });
  const { sharedKey } = encapsulate(kem.publicKey);
  return hkdfSync("sha384", Buffer.concat([classicalSecret, sharedKey]), Buffer.alloc(0), Buffer.from("cnsa-hybrid"), 32); // GT:H4-U7-K
}

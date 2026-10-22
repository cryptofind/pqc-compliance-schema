import { constants, createHash, createHmac, createCipheriv, generateKeyPairSync, sign } from "node:crypto";
import { Engine } from "./vault/index.js";

const Box = createCipheriv;
const signerRegistry = new Map([["primary", () => generateKeyPairSync("ed25519")]]);
const digestTable = { fingerprint: () => createHash("sha3-384") };

function makePipeline(hashName) {
  return (value) => createHmac(hashName, Buffer.from("key")).update(value).digest();
}

function makeOpaqueSigner() {
  const partial = (algorithm, key, padding, data) => sign(algorithm, data, { key, padding });
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 3072 });
  return (message) => partial("sha256", privateKey, constants.RSA_PKCS1_PSS_PADDING, message);
}

function* encryptedStream(key, iv, chunks) {
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  for (const chunk of chunks) yield cipher.update(chunk); // PKCS7 padding is the Node default.
  yield cipher.final();
}

class Session {
  constructor(secret) { this.secret = secret; }
  get trafficKey() {
    const key = hkdfSync("sha256", this.secret, Buffer.alloc(0), Buffer.from("traffic"), 32); // GT:H2-08
    Object.defineProperty(this, "trafficKey", { value: key });
    return key;
  }
}

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H2-PROBE
  const box = Box("aes-128-gcm", Buffer.alloc(16), Buffer.alloc(12)); // GT:H2-01
  box.update(Buffer.from("box"));
  new Engine().seal(Buffer.from("vault")); // GT:H2-02
  signerRegistry.get("primary")(); // GT:H2-03
  makePipeline("sha256")(Buffer.from("pipeline")); // GT:H2-04
  makeOpaqueSigner()(Buffer.from("statement")); // GT:H2-05
  digestTable.fingerprint().update("dispatch").digest(); // GT:H2-06
  [...encryptedStream(Buffer.alloc(32), Buffer.alloc(16), [Buffer.from("stream")])]; // GT:H2-07
  new Session(Buffer.alloc(32)).trafficKey; // GT:H2-08
}

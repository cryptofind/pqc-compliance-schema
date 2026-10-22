import { constants, createCipheriv, createHash, createHmac, generateKeyPairSync, hkdfSync, sign, publicEncrypt } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const config = (name) => readFileSync(resolve(here, "config", name), "utf8");

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H6-PROBE
  const cipherConfig = JSON.parse(config("crypto.json"));
  createCipheriv(cipherConfig.cipher, Buffer.alloc(32), Buffer.alloc(12)); // GT:H6-01
  const signing = config("signing.yaml");
  const curve = signing.match(/secp\d+r1/)[0];
  const hash = signing.match(/sha\d+/)[0];
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: curve }); // GT:H6-02
  sign(hash, Buffer.from("signed"), privateKey);
  const kdf = config("kdf.xml");
  hkdfSync(kdf.match(/sha\d+/)[0], Buffer.alloc(32), Buffer.alloc(0), Buffer.from("kdf"), 32); // GT:H6-03
  const transport = config("transport.toml");
  const keyBits = Number(transport.match(/key_bits\s*=\s*(\d+)/)[1]);
  const transportHash = transport.match(/hash\s*=\s*"([^"]+)"/)[1];
  const rsa = generateKeyPairSync("rsa", { modulusLength: keyBits }); // GT:H6-04
  publicEncrypt({ key: rsa.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: transportHash }, Buffer.from("transport"));
  const macHash = config("mac.ini").match(/hash\s*=\s*"([^"]+)"/)[1];
  createHmac(macHash, "mac-key").update("message").digest(); // GT:H6-05
  createHash(process.env.DIGEST ?? "sha224").update("digest").digest(); // GT:H6-06
  const env = config(".env");
  generateKeyPairSync(env.match(/ml-kem-\d+/)[0]); // GT:H6-07
  const deployment = readFileSync(resolve(here, "deploy", "docker-compose.yml"), "utf8");
  generateKeyPairSync(process.env.APP_KEX ?? deployment.match(/APP_KEX:\s*(\w+)/)[1]); // GT:H6-08
  createCipheriv(process.env.DATA_CIPHER, Buffer.alloc(32), Buffer.alloc(12)); // GT:H6-09
  const registry = [
    "aes-siv", // GT:H6-I01/registry
    "chacha20-poly1305", // GT:H6-I02/registry
    "ml-kem-768", // GT:H6-I03/registry
    "x448", // GT:H6-I04/registry
    "ed25519", // GT:H6-I05/registry
  ];
  return registry;
}

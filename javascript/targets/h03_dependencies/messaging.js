import nacl from "tweetnacl";
import { generateKeyPairSync } from "node:crypto";

export function sealMessage(message) {
  const keyPair = generateKeyPairSync("x25519"); // GT:H3-02a
  const secretboxKey = nacl.randomBytes(nacl.secretbox.keyLength);
  return nacl.secretbox(message, nacl.randomBytes(nacl.secretbox.nonceLength), secretboxKey); // GT:H3-01, GT:H3-02b
}

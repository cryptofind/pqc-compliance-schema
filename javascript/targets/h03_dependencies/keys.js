import { generateKeyPairSync, sign } from "node:crypto";

export function signMessage(message) {
  const { privateKey } = generateKeyPairSync("ed25519"); // GT:H3-03
  const { privateKey: ecKey } = generateKeyPairSync("ec", { namedCurve: "secp384r1" }); // GT:H3-05
  return [sign(null, message, privateKey), sign("sha384", message, ecKey)];
}

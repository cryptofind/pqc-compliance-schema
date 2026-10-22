import { createCipheriv, randomBytes } from "node:crypto";

const encoded = Buffer.from(
  "Y29uc3QgYWxnbyA9ICdjaGFjaGEyMC1wb2x5MTMwNSc7IGNyZWF0ZUNpcGhlcml2KGFsZ28sIGtleSwgaXYp",
  "base64",
); // GT:H1-06/def

export function runPayload(input) {
  const payloadText = encoded.toString("utf8");
  const match = payloadText.match(/'([^']+)'/);
  if (!match) throw new Error("encoded payload does not declare an algorithm");
  const algorithm = match[1];
  const cipher = createCipheriv(algorithm, randomBytes(32), randomBytes(12)); // GT:H1-06
  return cipher.update(input);
}

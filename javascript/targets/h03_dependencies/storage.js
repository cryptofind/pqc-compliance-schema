import { createCipheriv, createHmac, randomBytes } from "node:crypto";

export function encryptAtRest(data) {
  const cipher = createCipheriv("aes-128-cbc", randomBytes(16), randomBytes(16)); // GT:H3-08a
  const mac = createHmac("sha256", "storage-key").update(data).digest(); // GT:H3-08b
  return [cipher.update(data), mac];
}

import { createCipheriv, randomBytes } from "node:crypto";

export function sealKit(data) {
  const cipher = createCipheriv("id-aes256-wrap", randomBytes(32), Buffer.alloc(8)); // GT:H3-09
  return cipher.update(data);
}

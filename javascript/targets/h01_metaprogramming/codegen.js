import { hkdfSync } from "node:crypto";

const template = "return hkdfSync('sha384', material, salt, info, 32);"; // GT:H1-03/def
const generated = new Function("hkdfSync", "material", "salt", "info", template); // GT:H1-03/def

export function deriveSession(material) {
  return generated(hkdfSync, material, Buffer.alloc(0), Buffer.from("session")); // GT:H1-03
}

import * as crypto from "node:crypto";
import { compileRecordMacro } from "./macro_engine.js";

const protectExpanded = compileRecordMacro(`(data) => {
  const cipher = crypto.createCipheriv("$CIPHER$", crypto.randomBytes(32), crypto.randomBytes(12)); // GT:H1-01/def
  cipher.update(data);
  return crypto.generateKeyPairSync("$KEM$"); // GT:H1-02/def
}`);

export function protect(input) {
  return protectExpanded(input);
}

export function agreeSession() {
  return protect(Buffer.from("macro-expanded record"));
}

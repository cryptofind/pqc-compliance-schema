import { createHash } from "node:crypto";
import { sealMessage } from "./messaging.js";
import { createToken } from "./tokens.js";
import { encryptAtRest } from "./storage.js";
import { sealKit } from "./third_party/sealkit/index.js";

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H3-PROBE
  sealMessage(Buffer.from("message"));
  createToken({ subject: "user" });
  encryptAtRest(Buffer.from("secret"));
  sealKit(Buffer.from("vendored"));
}

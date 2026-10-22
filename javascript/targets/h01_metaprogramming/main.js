import { createHash } from "node:crypto";
import { protect, agreeSession } from "./records.js";
import { deriveSession } from "./codegen.js";
import { signEntry } from "./meta.js";
import { agree } from "./dynload.js";
import { runPayload } from "./payload.js";

export function main() {
  createHash("sha512").update("probe").digest(); // GT:H1-PROBE
  protect(Buffer.from("record"));
  agreeSession();
  deriveSession(Buffer.alloc(32)); // GT:H1-03/anchor
  signEntry(Buffer.from("entry"));
  agree();
  runPayload(Buffer.from("payload"));
}

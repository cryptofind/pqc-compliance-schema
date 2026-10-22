import * as crypto from "node:crypto";

export function compileRecordMacro(template) {
  const expanded = template
    .replace("$CIPHER$", "aes-256-gcm")
    .replace("$KEM$", "ml-kem-768");
  return new Function("crypto", `return (${expanded});`)(crypto);
}

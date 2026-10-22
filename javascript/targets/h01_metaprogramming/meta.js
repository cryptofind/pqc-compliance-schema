import { generateKeyPairSync, sign } from "node:crypto";

const EntrySigner = new Proxy(class {}, {
  construct() {
    return {
      sign(message) {
        const { privateKey } = generateKeyPairSync("ec", { namedCurve: "secp384r1" }); // GT:H1-04
        return sign("sha384", message, privateKey); // GT:H1-04
      },
    };
  },
});

export function signEntry(message) {
  return new EntrySigner().sign(message);
}

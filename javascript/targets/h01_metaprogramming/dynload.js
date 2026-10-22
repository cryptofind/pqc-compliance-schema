const cryptoModuleName = "node:" + "crypto";

export async function agree() {
  const crypto = await import(cryptoModuleName);
  return crypto.generateKeyPairSync("x25519"); // GT:H1-05
}

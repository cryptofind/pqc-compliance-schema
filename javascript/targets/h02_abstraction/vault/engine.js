import { createCipheriv, randomBytes } from "node:crypto";

export class Engine {
  seal(message) {
    const cipher = createCipheriv("chacha20-poly1305", randomBytes(32), randomBytes(12)); // GT:H2-02
    return cipher.update(message);
  }
}

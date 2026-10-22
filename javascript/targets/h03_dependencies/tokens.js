import jwt from "jsonwebtoken";
import { authenticator } from "otplib";
import { createHash, createHmac } from "node:crypto";

export function createToken(payload) {
  const defaultJwt = jwt.sign(payload, "secret"); // default HS256; GT:H3-04
  const oneTimeCode = authenticator.generate("shared-secret"); // default HMAC-SHA1; GT:H3-06a
  createHash("sha1").update(oneTimeCode).digest(); // GT:H3-06b
  createHmac("sha1", "secret").update(oneTimeCode).digest(); // GT:H3-07
  return { defaultJwt, oneTimeCode };
}

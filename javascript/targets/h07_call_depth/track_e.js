import { generateKeyPairSync, encapsulate, decapsulate } from "node:crypto";

export function e_entry_d00() {
  const pair = generateKeyPairSync("ml-kem-768"); // GT:H7-E-d00/keygen
  const { sharedKey, ciphertext } = encapsulate(pair.publicKey); // GT:H7-E-d00/op
  return decapsulate(pair.privateKey, ciphertext).equals(sharedKey);
}

export function e_entry_d04() { return _e_d04_h01(); }
function _e_d04_h01() {
  return _e_d04_h02();
}
function _e_d04_h02() {
  return _e_d04_h03();
}
function _e_d04_h03() {
  return _e_d04_h04();
}
function _e_d04_h04() {
  const pair = generateKeyPairSync("ml-kem-768"); // GT:H7-E-d04/keygen
  const { sharedKey, ciphertext } = encapsulate(pair.publicKey); // GT:H7-E-d04/op
  return decapsulate(pair.privateKey, ciphertext).equals(sharedKey);
}

export function e_entry_d16() { return _e_d16_h01(); }
function _e_d16_h01() {
  return _e_d16_h02();
}
function _e_d16_h02() {
  return _e_d16_h03();
}
function _e_d16_h03() {
  return _e_d16_h04();
}
function _e_d16_h04() {
  return _e_d16_h05();
}
function _e_d16_h05() {
  return _e_d16_h06();
}
function _e_d16_h06() {
  return _e_d16_h07();
}
function _e_d16_h07() {
  return _e_d16_h08();
}
function _e_d16_h08() {
  return _e_d16_h09();
}
function _e_d16_h09() {
  return _e_d16_h10();
}
function _e_d16_h10() {
  return _e_d16_h11();
}
function _e_d16_h11() {
  return _e_d16_h12();
}
function _e_d16_h12() {
  return _e_d16_h13();
}
function _e_d16_h13() {
  return _e_d16_h14();
}
function _e_d16_h14() {
  return _e_d16_h15();
}
function _e_d16_h15() {
  return _e_d16_h16();
}
function _e_d16_h16() {
  const pair = generateKeyPairSync("ml-kem-768"); // GT:H7-E-d16/keygen
  const { sharedKey, ciphertext } = encapsulate(pair.publicKey); // GT:H7-E-d16/op
  return decapsulate(pair.privateKey, ciphertext).equals(sharedKey);
}

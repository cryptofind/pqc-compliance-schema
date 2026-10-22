import { generateKeyPairSync, diffieHellman } from "node:crypto";

export function a_entry_d00() {
  const mine = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); // GT:H7-A-d00/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); // GT:H7-A-d00/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d00/op
}

export function a_entry_d01() { return _a_d01_h01(); }
function _a_d01_h01() {
  const mine = generateKeyPairSync("ec", { namedCurve: "secp384r1" }); // GT:H7-A-d01/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "secp384r1" }); // GT:H7-A-d01/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d01/op
}

export function a_entry_d02() { return _a_d02_h01(); }
function _a_d02_h01() {
  return _a_d02_h02();
}
function _a_d02_h02() {
  const mine = generateKeyPairSync("ec", { namedCurve: "secp521r1" }); // GT:H7-A-d02/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "secp521r1" }); // GT:H7-A-d02/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d02/op
}

export function a_entry_d03() { return _a_d03_h01(); }
function _a_d03_h01() {
  return _a_d03_h02();
}
function _a_d03_h02() {
  return _a_d03_h03();
}
function _a_d03_h03() {
  const mine = generateKeyPairSync("ec", { namedCurve: "secp224r1" }); // GT:H7-A-d03/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "secp224r1" }); // GT:H7-A-d03/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d03/op
}

export function a_entry_d04() { return _a_d04_h01(); }
function _a_d04_h01() {
  return _a_d04_h02();
}
function _a_d04_h02() {
  return _a_d04_h03();
}
function _a_d04_h03() {
  return _a_d04_h04();
}
function _a_d04_h04() {
  const mine = generateKeyPairSync("ec", { namedCurve: "secp256k1" }); // GT:H7-A-d04/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "secp256k1" }); // GT:H7-A-d04/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d04/op
}

export function a_entry_d06() { return _a_d06_h01(); }
function _a_d06_h01() {
  return _a_d06_h02();
}
function _a_d06_h02() {
  return _a_d06_h03();
}
function _a_d06_h03() {
  return _a_d06_h04();
}
function _a_d06_h04() {
  return _a_d06_h05();
}
function _a_d06_h05() {
  return _a_d06_h06();
}
function _a_d06_h06() {
  const mine = generateKeyPairSync("ec", { namedCurve: "brainpoolP256r1" }); // GT:H7-A-d06/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "brainpoolP256r1" }); // GT:H7-A-d06/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d06/op
}

export function a_entry_d08() { return _a_d08_h01(); }
function _a_d08_h01() {
  return _a_d08_h02();
}
function _a_d08_h02() {
  return _a_d08_h03();
}
function _a_d08_h03() {
  return _a_d08_h04();
}
function _a_d08_h04() {
  return _a_d08_h05();
}
function _a_d08_h05() {
  return _a_d08_h06();
}
function _a_d08_h06() {
  return _a_d08_h07();
}
function _a_d08_h07() {
  return _a_d08_h08();
}
function _a_d08_h08() {
  const mine = generateKeyPairSync("ec", { namedCurve: "brainpoolP384r1" }); // GT:H7-A-d08/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "brainpoolP384r1" }); // GT:H7-A-d08/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d08/op
}

export function a_entry_d12() { return _a_d12_h01(); }
function _a_d12_h01() {
  return _a_d12_h02();
}
function _a_d12_h02() {
  return _a_d12_h03();
}
function _a_d12_h03() {
  return _a_d12_h04();
}
function _a_d12_h04() {
  return _a_d12_h05();
}
function _a_d12_h05() {
  return _a_d12_h06();
}
function _a_d12_h06() {
  return _a_d12_h07();
}
function _a_d12_h07() {
  return _a_d12_h08();
}
function _a_d12_h08() {
  return _a_d12_h09();
}
function _a_d12_h09() {
  return _a_d12_h10();
}
function _a_d12_h10() {
  return _a_d12_h11();
}
function _a_d12_h11() {
  return _a_d12_h12();
}
function _a_d12_h12() {
  const mine = generateKeyPairSync("ec", { namedCurve: "brainpoolP512r1" }); // GT:H7-A-d12/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "brainpoolP512r1" }); // GT:H7-A-d12/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d12/op
}

export function a_entry_d16() { return _a_d16_h01(); }
function _a_d16_h01() {
  return _a_d16_h02();
}
function _a_d16_h02() {
  return _a_d16_h03();
}
function _a_d16_h03() {
  return _a_d16_h04();
}
function _a_d16_h04() {
  return _a_d16_h05();
}
function _a_d16_h05() {
  return _a_d16_h06();
}
function _a_d16_h06() {
  return _a_d16_h07();
}
function _a_d16_h07() {
  return _a_d16_h08();
}
function _a_d16_h08() {
  return _a_d16_h09();
}
function _a_d16_h09() {
  return _a_d16_h10();
}
function _a_d16_h10() {
  return _a_d16_h11();
}
function _a_d16_h11() {
  return _a_d16_h12();
}
function _a_d16_h12() {
  return _a_d16_h13();
}
function _a_d16_h13() {
  return _a_d16_h14();
}
function _a_d16_h14() {
  return _a_d16_h15();
}
function _a_d16_h15() {
  return _a_d16_h16();
}
function _a_d16_h16() {
  const mine = generateKeyPairSync("ec", { namedCurve: "secp192r1" }); // GT:H7-A-d16/keygen
  const peer = generateKeyPairSync("ec", { namedCurve: "secp192r1" }); // GT:H7-A-d16/keygen
  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // GT:H7-A-d16/op
}

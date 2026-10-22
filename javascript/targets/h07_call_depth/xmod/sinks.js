import { generateKeyPairSync } from "node:crypto";
export function c_d01(bits) { return generateKeyPairSync("rsa", { modulusLength: bits }); } // GT:H7-C-d01
export function c_d02(bits) { return generateKeyPairSync("rsa", { modulusLength: bits }); } // GT:H7-C-d02
export function c_d04(bits) { return generateKeyPairSync("rsa", { modulusLength: bits }); } // GT:H7-C-d04
export function c_d08(bits) { return generateKeyPairSync("rsa", { modulusLength: bits }); } // GT:H7-C-d08

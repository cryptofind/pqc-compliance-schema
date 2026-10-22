import { generateKeyPairSync } from "node:crypto";

export function d_entry_d01() { return new D01Hop01(3072).run(); } // GT:H7-D-d01/src

class D01Hop01 {
  constructor(bits) { this.bits = bits; }
  run() {
    return generateKeyPairSync("rsa", { modulusLength: this.bits }); // GT:H7-D-d01
  }
}

export function d_entry_d02() { return new D02Hop01(2048).run(); } // GT:H7-D-d02/src

class D02Hop01 {
  constructor(bits) { this.bits = bits; }
  run() {
    return new D02Hop02(this.bits).run();
  }
}

class D02Hop02 {
  constructor(bits) { this.bits = bits; }
  run() {
    return generateKeyPairSync("rsa", { modulusLength: this.bits }); // GT:H7-D-d02
  }
}

export function d_entry_d04() { return new D04Hop01(4096).run(); } // GT:H7-D-d04/src

class D04Hop01 {
  constructor(bits) { this.bits = bits; }
  run() {
    return new D04Hop02(this.bits).run();
  }
}

class D04Hop02 {
  constructor(bits) { this.bits = bits; }
  run() {
    return new D04Hop03(this.bits).run();
  }
}

class D04Hop03 {
  constructor(bits) { this.bits = bits; }
  run() {
    return new D04Hop04(this.bits).run();
  }
}

class D04Hop04 {
  constructor(bits) { this.bits = bits; }
  run() {
    return generateKeyPairSync("rsa", { modulusLength: this.bits }); // GT:H7-D-d04
  }
}

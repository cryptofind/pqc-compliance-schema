import * as sinks from "./xmod/sinks.js";
import * as level01 from "./xmod/level01.js";
import * as level02 from "./xmod/level02.js";
import * as level03 from "./xmod/level03.js";
import * as level04 from "./xmod/level04.js";
import * as level05 from "./xmod/level05.js";
import * as level06 from "./xmod/level06.js";
import * as level07 from "./xmod/level07.js";

export function c_entry_d01() { return sinks.c_d01(4096); } // GT:H7-C-d01/src
export function c_entry_d02() { return level01.c_d02(2048); } // GT:H7-C-d02/src
export function c_entry_d04() { return level01.c_d04(3072); } // GT:H7-C-d04/src
export function c_entry_d08() { return level01.c_d08(4096); } // GT:H7-C-d08/src

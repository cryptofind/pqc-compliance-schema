import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "targets", "h07_call_depth");
const depths = [0, 1, 2, 3, 4, 6, 8, 12, 16];
const curves = new Map([
  [0, "prime256v1"], [1, "secp384r1"], [2, "secp521r1"], [3, "secp224r1"],
  [4, "secp256k1"], [6, "brainpoolP256r1"], [8, "brainpoolP384r1"],
  [12, "brainpoolP512r1"], [16, "secp192r1"],
]);
const sizes = new Map([[0, 2048], [1, 3072], [2, 4096], [3, 2048], [4, 3072], [6, 4096], [8, 2048], [12, 3072], [16, 4096]]);
const cDepths = [1, 2, 4, 8];
const cSizes = new Map([[1, 4096], [2, 2048], [4, 3072], [8, 4096]]);
const dDepths = [1, 2, 4];
const dSizes = new Map([[1, 3072], [2, 2048], [4, 4096]]);
const eDepths = [0, 4, 16];
const files = new Map();

function add(path, contents) {
  files.set(path, `${contents.trim()}\n`);
}

function chain(prefix, depth, body) {
  const names = Array.from({ length: depth }, (_, index) => `_${prefix}_d${String(depth).padStart(2, "0")}_h${String(index + 1).padStart(2, "0")}`);
  const blocks = [];
  for (let i = 0; i < depth; i++) {
    const name = names[i];
    blocks.push(`function ${name}() {`);
    blocks.push(i + 1 < depth ? `  return ${names[i + 1]}();` : body);
    blocks.push("}");
  }
  return blocks.join("\n");
}

const trackA = ['import { generateKeyPairSync, diffieHellman } from "node:crypto";'];
for (const depth of depths) {
  const marker = `GT:H7-A-d${String(depth).padStart(2, "0")}`;
  const curve = curves.get(depth);
  const call = `  const mine = generateKeyPairSync("ec", { namedCurve: "${curve}" }); // ${marker}/keygen\n  const peer = generateKeyPairSync("ec", { namedCurve: "${curve}" }); // ${marker}/keygen\n  return diffieHellman({ privateKey: mine.privateKey, publicKey: peer.publicKey }); // ${marker}/op`;
  if (depth === 0) {
    trackA.push(`export function a_entry_d00() {\n${call}\n}`);
  } else {
    trackA.push(`export function a_entry_d${String(depth).padStart(2, "0")}() { return _a_d${String(depth).padStart(2, "0")}_h01(); }\n${chain("a", depth, call)}`);
  }
}
add("track_a.js", trackA.join("\n\n"));

const trackB = ['import { generateKeyPairSync } from "node:crypto";'];
for (const depth of depths) {
  const marker = `GT:H7-B-d${String(depth).padStart(2, "0")}`;
  if (depth === 0) {
    trackB.push(`export function b_entry_d00() { return generateKeyPairSync("rsa", { modulusLength: 2048 }); } // ${marker}`);
  } else {
    const size = sizes.get(depth);
    const names = Array.from({ length: depth }, (_, index) => `_b_d${String(depth).padStart(2, "0")}_h${String(index + 1).padStart(2, "0")}`);
    trackB.push(`export function b_entry_d${String(depth).padStart(2, "0")}() { return ${names[0]}(${size}); } // ${marker}/src`);
    for (let i = 0; i < depth; i++) {
      trackB.push(
        i + 1 < depth
          ? `function ${names[i]}(bits) { return ${names[i + 1]}(bits); }`
          : `function ${names[i]}(bits) { return generateKeyPairSync("rsa", { modulusLength: bits }); // ${marker}\n}`,
      );
    }
  }
}
add("track_b.js", trackB.join("\n\n"));

const trackCImports = ['import * as sinks from "./xmod/sinks.js";'];
for (let level = 1; level <= 7; level++) trackCImports.push(`import * as level${String(level).padStart(2, "0")} from "./xmod/level${String(level).padStart(2, "0")}.js";`);
const entryCalls = [];
for (const depth of cDepths) {
  const functionName = `c_d${String(depth).padStart(2, "0")}`;
  const marker = `GT:H7-C-d${String(depth).padStart(2, "0")}`;
  const target = depth === 1 ? "sinks" : "level01";
  entryCalls.push(`export function c_entry_d${String(depth).padStart(2, "0")}() { return ${target}.${functionName}(${cSizes.get(depth)}); } // ${marker}/src`);
}
add("track_c.js", `${trackCImports.join("\n")}\n\n${entryCalls.join("\n")}`);
const sinkFunctions = cDepths.map((depth) => {
  const marker = `GT:H7-C-d${String(depth).padStart(2, "0")}`;
  return `export function c_d${String(depth).padStart(2, "0")}(bits) { return generateKeyPairSync("rsa", { modulusLength: bits }); } // ${marker}`;
});
add("xmod/sinks.js", `import { generateKeyPairSync } from "node:crypto";\n${sinkFunctions.join("\n")}`);

for (let level = 1; level <= 7; level++) {
  const functions = [];
  const imports = new Set();
  for (const depth of cDepths.filter((d) => d > level)) {
    const name = `c_d${String(depth).padStart(2, "0")}`;
    const next = level >= depth - 1 ? "sinks" : `level${String(level + 1).padStart(2, "0")}`;
    imports.add(next);
    functions.push(`export function ${name}(bits) { return ${next}.${name}(bits); }`);
  }
  if (functions.length) {
    const importLines = [...imports].map((name) => `import * as ${name} from "./${name === "sinks" ? "sinks" : `${name}.js`}";`);
    add(`xmod/level${String(level).padStart(2, "0")}.js`, `${importLines.join("\n")}\n${functions.join("\n")}`);
  }
}

const trackD = ['import { generateKeyPairSync } from "node:crypto";'];
for (const depth of dDepths) {
  const marker = `GT:H7-D-d${String(depth).padStart(2, "0")}`;
  trackD.push(`export function d_entry_d${String(depth).padStart(2, "0")}() { return new D${String(depth).padStart(2, "0")}Hop01(${dSizes.get(depth)}).run(); } // ${marker}/src`);
  for (let hop = 1; hop <= depth; hop++) {
    const next = hop < depth
      ? `return new D${String(depth).padStart(2, "0")}Hop${String(hop + 1).padStart(2, "0")}(this.bits).run();`
      : `return generateKeyPairSync("rsa", { modulusLength: this.bits }); // ${marker}`;
    trackD.push(`class D${String(depth).padStart(2, "0")}Hop${String(hop).padStart(2, "0")} {
  constructor(bits) { this.bits = bits; }
  run() {
    ${next}
  }
}`);
  }
}
add("track_d.js", trackD.join("\n\n"));

const trackE = ['import { generateKeyPairSync, encapsulate, decapsulate } from "node:crypto";'];
for (const depth of eDepths) {
  const marker = `GT:H7-E-d${String(depth).padStart(2, "0")}`;
  const body = `  const pair = generateKeyPairSync("ml-kem-768"); // ${marker}/keygen\n  const { sharedKey, ciphertext } = encapsulate(pair.publicKey); // ${marker}/op\n  return decapsulate(pair.privateKey, ciphertext).equals(sharedKey);`;
  if (depth === 0) trackE.push(`export function e_entry_d00() {\n${body}\n}`);
  else trackE.push(`export function e_entry_d${String(depth).padStart(2, "0")}() { return _e_d${String(depth).padStart(2, "0")}_h01(); }\n${chain("e", depth, body)}`);
}
add("track_e.js", trackE.join("\n\n"));

const depthsToCall = [
  ...depths.map((d) => `  trackA.a_entry_d${String(d).padStart(2, "0")}();`),
  ...depths.map((d) => `  trackB.b_entry_d${String(d).padStart(2, "0")}();`),
  ...cDepths.map((d) => `  trackC.c_entry_d${String(d).padStart(2, "0")}();`),
  ...dDepths.map((d) => `  trackD.d_entry_d${String(d).padStart(2, "0")}();`),
  ...eDepths.map((d) => `  trackE.e_entry_d${String(d).padStart(2, "0")}();`),
];
add("main.js", `import { createHash } from "node:crypto";
import * as trackA from "./track_a.js";
import * as trackB from "./track_b.js";
import * as trackC from "./track_c.js";
import * as trackD from "./track_d.js";
import * as trackE from "./track_e.js";
export function main() {
  createHash("sha512").update("probe").digest(); // GT:H7-PROBE
${depthsToCall.join("\n")}
}`);
add("package.json", JSON.stringify({ name: "pqc-benchmark-h07-call-depth", private: true, type: "module" }, null, 2));

await mkdir(root, { recursive: true });
for (const [path, contents] of files) {
  const destination = resolve(root, path);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, `${contents.trim()}\n`, "utf8");
}
console.log(`Generated ${files.size} H7 JavaScript files at ${root}`);

import * as fs from "fs";
import * as path from "path";
import { bigIntToUint8Array, bitArrayToUint8Array } from "./utils";

const args = process.argv.slice(2);
const filename = args[0];
const ell = parseInt(args[1]);
const outFile = args[2];

if (!filename) {
  console.error("Please provide the public.json to parse");
  process.exit(1);
}

if (!ell) {
  console.error("Please provide the length of the comparator");
  process.exit(1);
}

function loadJSON(filename: string): string[] {
  try {
    const filePath = path.resolve(filename);
    const fileContent = fs.readFileSync(filePath, "utf-8");
    const jsonData = JSON.parse(fileContent);
    return jsonData;
  } catch (error) {
    const err = error as Error;
    console.error("Error reading JSON file:", err.message);
    process.exit(1);
  }
}

const proverLabels: string[] = [];
const proverSelectors: string[] = [];
const jsonData = loadJSON(filename);

let index = 0;
for (let i = 0; i < ell; i++) {
  proverLabels.push(jsonData[index]);
  index++;
}
for (let i = 0; i < ell; i++) {
  proverSelectors.push(jsonData[index]);
  index++;
}

const senderMessages: string[][][] = [];
for (let i = 0; i < ell; i++) {
  const currentSM: string[][] = [];
  for (let j = 0; j < 2; j++) {
    const currentSubSM: string[] = [];
    for (let k = 0; k < 5; k++) {
      currentSubSM.push(jsonData[index]);
      index++;
    }
    currentSM.push(currentSubSM);
  }
  senderMessages.push(currentSM);
}

const gcOut: [string[], string[]] = [[], []];
for (let i = 0; i < 2; i++) {
  const bitArray: string[] = [];
  for (let j = 0; j < 254; j++) {
    bitArray.push(jsonData[index]);
    index++;
  }
  gcOut[i] = bitArray;
}

const gcTGs: string[][] = [];
for (let i = 0; i < ell; i++) {
  const bitArray: string[] = [];
  for (let j = 0; j < 254; j++) {
    bitArray.push(jsonData[index]);
    index++;
  }
  gcTGs.push(bitArray);
}

const gcTEs: string[][] = [];
for (let i = 0; i < ell; i++) {
  const bitArray: string[] = [];
  for (let j = 0; j < 254; j++) {
    bitArray.push(jsonData[index]);
    index++;
  }
  gcTEs.push(bitArray);
}

const g: [string, string] = [jsonData[index], jsonData[index + 1]];
index += 2;

const receiverMessages: [[string, string], [string, string]][] = [];
for (let i = 0; i < ell; i++) {
  const pkPair: [[string, string], [string, string]] = [
    ["", ""],
    ["", ""],
  ];
  for (let j = 0; j < 2; j++) {
    const pk: [string, string] = ["", ""];
    for (let k = 0; k < 2; k++) {
      pk[k] = jsonData[index];
      index++;
    }
    pkPair[j] = pk;
  }
  receiverMessages.push(pkPair);
}

const rEncodes: [[string, string], [string, string]][] = [];
for (let i = 0; i < ell; i++) {
  const rePair: [[string, string], [string, string]] = [
    ["", ""],
    ["", ""],
  ];
  for (let j = 0; j < 2; j++) {
    const rE: [string, string] = ["", ""];
    for (let k = 0; k < 2; k++) {
      rE[k] = jsonData[index];
      index++;
    }
    rePair[j] = rE;
  }
  rEncodes.push(rePair);
}

// Begin serialization
let serializedOutput = new Uint8Array([]);
for (const label of proverLabels) {
  const labBytes = bigIntToUint8Array(BigInt(label));
  serializedOutput = new Uint8Array([...serializedOutput, ...labBytes]);
}
const selectorsArray = bitArrayToUint8Array(proverSelectors);
serializedOutput = new Uint8Array([...serializedOutput, ...selectorsArray]);

for (const sm of senderMessages) {
  for (const subSM of sm) {
    for (const fv of subSM) {
      const fvBytes = bigIntToUint8Array(BigInt(fv));
      serializedOutput = new Uint8Array([...serializedOutput, ...fvBytes]);
    }
  }
}

for (const tg of gcTGs) {
  serializedOutput = new Uint8Array([
    ...serializedOutput,
    ...bitArrayToUint8Array(tg),
  ]);
}
for (const te of gcTEs) {
  serializedOutput = new Uint8Array([
    ...serializedOutput,
    ...bitArrayToUint8Array(te),
  ]);
}

if (outFile) {
  fs.writeFileSync(outFile, serializedOutput);
}

// Estimate cost to double-check
let estimatedCost = 0;

estimatedCost += ell * 32; // 32 bytes for each prover label
estimatedCost += 32; // Bytes to contain each prover selector
estimatedCost += ell * 10 * 32; // Sender messages
estimatedCost += ell * 32; // TGs
estimatedCost += ell * 32; // TEs
console.log(
  `Estimated Cost: ${
    estimatedCost + 128
  } bytes (including 128 bytes of Groth16 proof)`
);

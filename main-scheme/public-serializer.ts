import * as fs from "fs";
import * as path from "path";

import yargs, { demandOption, describe } from "yargs";
import { hideBin } from "yargs/helpers";

import { bigIntToUint8Array } from "./src/utils";

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

async function main() {
  const args = yargs(hideBin(process.argv))
    .option("n", {
      describe: "The number of digits",
      type: "number",
      demandOption: true,
      default: 10,
    })
    .option("b", {
      describe: "The base",
      type: "number",
      demandOption: true,
      default: 10,
    })
    .option("f", {
      describe: "The public file to serialize",
      type: "string",
      demandOption: true,
      default: "public.json",
    })
    .option("o", {
      describe: "The output file to write to",
      type: "string",
      demandOption: true,
      default: "public.bin",
    })
    .parseSync();

  const jsonData = loadJSON(args.f);

  // q, g[2], h[2], pk[n][b][2][2]
  // Public inputs already known to auditor
  let index = 1 + 2 + 2 + args.n * args.b * 4;

  // Start of outputs (what we need to send to the auditor)
  const betaStar: string[] = [];
  for (let i = 0; i < 2; i++) {
    betaStar.push(jsonData[index]);
    index++;
  }

  const first: string[] = [];
  for (let i = 0; i < 8; i++) {
    first.push(jsonData[index]);
    index++;
  }

  const middle: string[][] = [];
  for (let i = 0; i < args.n - 2; i++) {
    const cts: string[] = [];
    for (let j = 0; j < 8; j++) {
      cts.push(jsonData[index]);
      index++;
    }
    middle.push(cts);
  }

  const last: string[] = [];
  for (let i = 0; i < 4; i++) {
    last.push(jsonData[index]);
    index++;
  }

  // Begin Serialization
  let serializedOutput = new Uint8Array([]);

  for (const val of betaStar) {
    const valBytes = bigIntToUint8Array(BigInt(val));
    serializedOutput = new Uint8Array([...serializedOutput, ...valBytes]);
  }

  for (const val of first) {
    const valBytes = bigIntToUint8Array(BigInt(val));
    serializedOutput = new Uint8Array([...serializedOutput, ...valBytes]);
  }
  for (const l of middle) {
    for (const val of l) {
      const valBytes = bigIntToUint8Array(BigInt(val));
      serializedOutput = new Uint8Array([...serializedOutput, ...valBytes]);
    }
  }
  for (const val of last) {
    const valBytes = bigIntToUint8Array(BigInt(val));
    serializedOutput = new Uint8Array([...serializedOutput, ...valBytes]);
  }

  fs.writeFileSync(args.o, serializedOutput);

  let estimatedCost = 0;
  estimatedCost += 2 * 32; // 32 bytes for each part of betaStar
  estimatedCost += 8 * 32; // 32 bytes for each first element
  estimatedCost += (args.n - 2) * 8 * 32; // middle
  estimatedCost += 4 * 32; // last

  console.log(
    `Estimated Cost: ${
      estimatedCost + 128
    } bytes (Including 128 bytes for Groth16 proof)`
  );
}

main();

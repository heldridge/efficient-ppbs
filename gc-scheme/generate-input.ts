import fs from "fs";

import { genPrivKey, genPubKey, genRandomSalt, PubKey } from "maci-crypto";
import { babyJub } from "circomlib";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { BabyJubPoint } from "./elgamal-babyjub";

import { sampleOffsetViaBigInt, WireValue } from "./gates";
import { sampleBabyJubPoint, bigIntToString, multiPairEncode } from "./utils";
import { multiSenderMessage } from "./ot";
import { promisify } from "util";

const writeFileAsync = promisify(fs.writeFile);

function randomBit() {
  return Math.random() < 0.5 ? 0 : 1;
}

async function main() {
  // Parse args
  const args = yargs(hideBin(process.argv))
    .option("ell", {
      describe: "The length of the comparator",
      type: "number",
      demandOption: true,
      default: 1,
    })
    .option("o", {
      describe: "The file to write output to",
      type: "string",
      demandOption: true,
      default: "input.json",
    })
    .parseSync();

  // Generate prover input
  const proverInput: (0 | 1)[] = Array.from({ length: args.ell }, () =>
    randomBit()
  );
  // console.log(`\nProver input: ${proverInput}`);

  const offset = sampleOffsetViaBigInt();
  // console.log(`\noffset: ${offset}`);

  const xInputs: [WireValue, WireValue][] = Array.from(
    { length: args.ell },
    () => {
      const wv = WireValue.sampleViaBigInt();
      return [wv, WireValue.xor(wv, offset)];
    }
  );

  // console.log("\nxInputs:");
  // for (let curr of xInputs) {
  //   console.log(`(${curr[0]}, ${curr[1]})`);
  // }

  const yInputs: [WireValue, WireValue][] = Array.from(
    { length: args.ell },
    () => {
      const wv = WireValue.sampleViaBigInt();
      return [wv, WireValue.xor(wv, offset)];
    }
  );
  // console.log("\nyInputs:");
  // for (let curr of yInputs) {
  //   console.log(`(${curr[0]}, ${curr[1]})`);
  // }

  const receiverMessages: [PubKey, PubKey][] = Array.from(
    { length: args.ell },
    () => [genPubKey(genPrivKey()), genPubKey(genPrivKey())]
  );

  // console.log("\nreceiverMessages:");
  // for (let curr of receiverMessages) {
  //   console.log(`(${curr[0]}, ${curr[1]})`);
  // }

  const rEncodes: [BabyJubPoint, BabyJubPoint][] = Array.from(
    { length: args.ell },
    () => [sampleBabyJubPoint(), sampleBabyJubPoint()]
  );
  // console.log("\nrEncodes:");
  // for (let curr of rEncodes) {
  //   console.log(`(${curr[0].x}, ${curr[1].x})`);
  // }

  const rEncrypt = genRandomSalt() as bigint;
  // console.log(`\nrEncrypt: ${rEncrypt}`);

  const g = babyJub.Base8.map(bigIntToString);

  const proverLabels = yInputs.map((l) =>
    l.map((wv) => String(wv.toHashable()))
  );
  const proverSelectors = yInputs.map((l) =>
    l.map((wv) => String(wv.selector))
  );
  const receiverLabels = xInputs.map((l) => l.map((wv) => wv.toHashable())) as [
    bigint,
    bigint
  ][];
  const receiverSelectors = xInputs.map((l) =>
    l.map((wv) => String(wv.selector))
  );

  const input = {
    // Prover info
    proverLabels: proverLabels,
    proverSelectors: proverSelectors,
    proverInput: proverInput,

    // OT Info
    receiverLabels: receiverLabels.map((l) => l.map(String)),
    receiverSelectors: receiverSelectors.map((l) => l.map(String)),
    receiverMessages: receiverMessages.map((pair) =>
      pair.map((key) => key.map(String))
    ),
    rEncodes: rEncodes.map((pair) =>
      pair.map((point) => [point.x, point.y].map(String))
    ),
    rEncrypt: String(rEncrypt),
    g: g.map(String),
    offset: offset.toBitArray(),
  };

  await writeFileAsync(args.o, JSON.stringify(input));
}

main();

import fs from "fs";

import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { Base8 } from "@zk-kit/baby-jubjub";

import { rrVECD } from "./src/vecd";
import {
  genRandomBabyJubPoint,
  genRandomBabyJubScalar,
  toBaseArray,
} from "./src/utils";
import { ElGamalMatchReveal } from "./src/pke";

async function main() {
  const args = yargs(hideBin(process.argv))
    .option("b", {
      describe: "The base of the scheme",
      type: "number",
      demandOption: true,
      default: 10,
    })
    .option("n", {
      describe: "The number of digits",
      type: "number",
      demandOption: true,
      default: 10,
    })
    .option("thr", {
      describe: "The threshold to use in keygen",
      type: "number",
      demandOption: true,
      default: 4,
    })
    .option("o", {
      describe: "The file to write output to",
      type: "string",
      demandOption: true,
      default: "input.json",
    })
    .parseSync();

  const params = rrVECD.setup(args.n, args.b);
  const keypair = rrVECD.keyGen(params, args.thr);
  const baseArray = toBaseArray(args.n, args.thr, args.b);

  const msg = genRandomBabyJubPoint();

  const otpStarRand = genRandomBabyJubScalar();
  const otpRands = Array.from({ length: args.n - 1 }, () => [
    genRandomBabyJubScalar(),
    genRandomBabyJubScalar(),
  ]);
  const rReveal = genRandomBabyJubScalar();
  const rMatch = genRandomBabyJubScalar();

  const input = {
    q: String(params.pke.q),
    g: params.pke.g.map(String),
    h: params.pke.h.map(String),
    pk: keypair.pk.map((l) =>
      l.map((p) => [p.X.map(String), p.XBar.map(String)])
    ),
    baseArray: baseArray.map(String),
    m: msg.map(String),
    otpStarRand: String(otpStarRand),
    otpRands: otpRands.map((l) => l.map((r) => String(r))),
    rReveal: String(rReveal),
    rMatch: String(rMatch),
  };

  fs.writeFileSync(args.o, JSON.stringify(input));
}

main();

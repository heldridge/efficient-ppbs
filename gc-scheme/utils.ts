import assert = require("assert");
import { babyJub } from "circomlib";
import { genPrivKey, genPubKey } from "maci-crypto";
import { randomBytes } from "crypto";

import { BabyJubPoint, Message, ElGamalCiphertext } from "./elgamal-babyjub";

export function sampleBytes(numBytes: number): Uint8Array {
  const arr = new Uint8Array(numBytes);
  crypto.getRandomValues(arr);
  return arr;
}

export function bitArrayMult(bit: number, array: Uint8Array) {
  return array.map((val) => val * bit);
}

export function bigIntToBitArray(b: bigint): string[] {
  let arr = Array.from(b.toString(2));
  let paddingArray = new Array(Math.max(0, 253 - arr.length)).fill("0");
  return paddingArray.concat(arr).reverse();
}

export function bigIntToUint8Array(bigint: bigint): Uint8Array {
  const byteLength = 32; // Fixed length of 32 bytes
  const uint8Array = new Uint8Array(byteLength);
  const byteMask = BigInt(0xff);
  const zero = BigInt(0);
  const shiftAmount = BigInt(8);

  // Fill the Uint8Array with the bigint value
  for (let i = byteLength - 1; i >= 0 && bigint > zero; i--) {
    uint8Array[i] = Number(bigint & byteMask);
    bigint = bigint >> shiftAmount;
  }

  return uint8Array;
}

export function bitArrayToBigInt(bits: string[]): bigint {
  bits.reverse();
  const biStr = "" + bits.join("");
  const bi = BigInt("0b" + biStr);
  return bi;
}

export function bitArrayToUint8Array(bits: string[]): Uint8Array {
  return bigIntToUint8Array(bitArrayToBigInt(bits));
}

export function uint8ArrayToBigint(uint8Array: Uint8Array): bigint {
  let bigint = BigInt(0);
  const shiftAmount = BigInt(8);

  for (let i = 0; i < uint8Array.length; i++) {
    bigint = (bigint << shiftAmount) + BigInt(uint8Array[i]);
  }
  return bigint;
}

export function uint8ArrayToBitArray(uint8Array: Uint8Array): string[] {
  const bits: string[] = [];

  for (const byte of uint8Array) {
    // Convert the byte to a binary string and pad it to 8 bits
    const byteString = byte.toString(2).padStart(8, "0");

    // Split the binary string into individual bits and add to the bits array
    bits.push(...byteString.split(""));
  }

  // Drop first 3 bits
  return bits.slice(3).reverse();
}

export class IDGen {
  currentID: bigint = BigInt(0);

  next(): bigint {
    this.currentID++;
    return this.currentID;
  }
}

export function babyEncode(m: bigint, r: BabyJubPoint): Message {
  assert(babyJub.inSubgroup([r.x, r.y]));

  const xIncrement = babyJub.F.e(babyJub.F.sub(r.x, m));

  assert(xIncrement >= BigInt(0));

  return { point: r, xIncrement };
}

export function multiBabyEncode(ms: bigint[], rs: BabyJubPoint[]): Message[] {
  const res = [];
  for (let i = 0; i < ms.length; i++) {
    res.push(babyEncode(ms[i], rs[i]));
  }
  return res;
}

export function multiPairEncode(
  pairs: [bigint, bigint][],
  rs: [BabyJubPoint, BabyJubPoint][]
): [Message, Message][] {
  const res: [Message, Message][] = [];
  for (let i = 0; i < pairs.length; i++) {
    res.push([
      babyEncode(pairs[i][0], rs[i][0]),
      babyEncode(pairs[i][1], rs[i][1]),
    ]);
  }
  return res;
}

export function sampleBabyJubPoint(): BabyJubPoint {
  const randomVal = genPrivKey();
  const randomPoint = genPubKey(randomVal);

  return {
    x: randomPoint[0],
    y: randomPoint[1],
  };
}

export function sampleBabyJubValue(): bigint {
  return sampleBabyJubPoint().x.valueOf();
}

export function bigIntToString(bi: bigint): string {
  return `${bi}`;
}

export function badBigIntToString(bi: BigInt): string {
  return bigIntToString(bi.valueOf());
}

export function sampleInt253() {
  // Create a buffer with enough space to hold 253 bits (32 bytes)
  const buffer = randomBytes(32);

  // Create a BigInt from the buffer
  let randomValue = BigInt(0);
  for (let i = 0; i < buffer.length; i++) {
    randomValue = (randomValue << BigInt(8)) + BigInt(buffer[i]);
  }

  // Mask off any extra bits beyond 253
  randomValue = randomValue & ((BigInt(1) << BigInt(253)) - BigInt(1));

  return randomValue;
}

export function flattenElGamalCiphertext(egct: ElGamalCiphertext): string[] {
  return [egct.c1.x, egct.c1.y, egct.c2.x, egct.c2.y, egct.xIncrement].map(
    (bi) => bigIntToString(bi.valueOf())
  );
}

// Takes an array like [[a, b, c], [x, y, z]] and returns
//[[a, x], [b, y], [c, z]]
export function zipArray<T>(arr: [T[], T[]]): [T, T][] {
  const res: [T, T][] = [];

  for (let i = 0; i < arr[0].length; i++) {
    res.push([arr[0][i], arr[1][i]]);
  }

  return res;
}

export function unzipArray<T>(arr: [T, T][]): [T[], T[]] {
  const res: [T[], T[]] = [[], []];

  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];

    res[0].push(item[0]);
    res[1].push(item[1]);
  }

  return res;
}

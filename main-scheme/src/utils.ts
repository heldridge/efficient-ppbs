import { randomBytes } from "crypto";

import {
  Point,
  Fr,
  mulPointEscalar,
  Base8,
  addPoint,
} from "@zk-kit/baby-jubjub";

export type BJPoint = Point<bigint>;

export function genRandomBabyJubScalar(): bigint {
  let r = BigInt(
    "2736030358979909402780800718157159386076813972158567259200215660948447373041"
  );
  let val = r;

  while (val >= r) {
    val = BigInt(`0x${randomBytes(32).toString("hex")}`);
  }
  return val;
}

export function genRandomBabyJubPoint(): BJPoint {
  return mulPointEscalar(Base8, genRandomBabyJubScalar());
}

export function babyJubInverse(p: BJPoint): BJPoint {
  return [Fr.e(p[0] * BigInt(-1)), p[1]];
}

export function babyJubEqual(a: BJPoint, b: BJPoint): boolean {
  return a[0] === b[0] && a[1] === b[1];
}

export function babyJubPointFromString(s: string): BJPoint {
  return mulPointEscalar(Base8, BigInt(s));
}

// Subtract a from b
export function babyJubSubtract(a: BJPoint, b: BJPoint): BJPoint {
  return addPoint(babyJubInverse(a), b);
}

export function toBaseArray(n: number, thr: number, b: number): number[] {
  if (thr < 0 || b <= 2) {
    throw new Error(
      "Invalid input: thr must be non-negative and b must be greater than 2"
    );
  }

  const minDigits = Math.floor(Math.log(thr) / Math.log(b)) + 1;
  if (n < minDigits) {
    throw new Error(
      `Insufficient digits: at least ${minDigits} digits are needed to represent ${thr} in base ${b}`
    );
  }

  const result: number[] = new Array(n).fill(0);
  let remaining = thr;

  for (let i = n - 1; i >= 0; i--) {
    result[i] = remaining % b;
    remaining = Math.floor(remaining / b);
  }

  return result;
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

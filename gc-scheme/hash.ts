import { poseidon } from "@big-whale-labs/poseidon";
import { WireValue } from "./gates";

export type Ciphertext = WireValue;
export type HashOutput = WireValue;

export interface HashFunction {
  outputLengthBytes: number;
  hash: (inputs: bigint[]) => HashOutput;
}

export function convertPoseidonOutput(posOut: bigint): HashOutput {
  return WireValue.fromBigInt(posOut);
}

export class Poseidon implements HashFunction {
  outputLengthBytes = -1;

  hash(inputs: bigint[]): HashOutput {
    return convertPoseidonOutput(poseidon(inputs));
  }

  hashRaw(inputs: bigint[]): bigint {
    return poseidon(inputs);
  }
}

import { babyJub } from "circomlib";

import {
    sampleBytes,
    bitArrayMult,
    uint8ArrayToBigint,
    IDGen,
    uint8ArrayToBitArray,
    bitArrayToUint8Array,
    bigIntToBitArray,
    bitArrayToBigInt,
    sampleInt253,
} from "./utils";
import { Ciphertext, HashFunction } from "./hash";

export type WireId = string;
export type GateId = string;
export type HashableWireValue = bigint;
export type EncryptableWireValue = bigint;

function xorArrays(a: Uint8Array, b: Uint8Array) {
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

export class WireValue {
    // Represents the garbled value of a wire
    // Contains the label and selector
    // Label is stored as all other bits, with the first bit set to 0

    selector: number;
    label: Uint8Array;

    constructor(label: Uint8Array, selector: number) {
        this.label = label;
        this.selector = selector;
    }

    static fromBigInt(val: bigint): WireValue {
        if (val >= babyJub.p) {
            throw new Error("val must be less than babyJub prime");
        }

        const bitArray = bigIntToBitArray(val);
        // Take the lsb for the selector
        const sel = Number(bitArray[0]);
        return new WireValue(bitArrayToUint8Array(bitArray.slice(1)), sel);
    }

    static sample(numBytes: number) {
        let bytes = sampleBytes(numBytes);
        bytes[0] &= 0b00011111;

        let bit = sampleBytes(1)[0] >> 7;

        return new WireValue(bytes, bit);
    }

    static sampleViaBigInt() {
        return WireValue.fromBigInt(sampleInt253());
    }

    static xor(a: WireValue, b: WireValue): WireValue {
        return new WireValue(
            xorArrays(a.label, b.label),
            a.selector ^ b.selector,
        );
    }

    public toHashable(): HashableWireValue {
        return uint8ArrayToBigint(this.label);
    }

    public toEncryptable(): EncryptableWireValue {
        return bitArrayToBigInt(this.toBitArray());
    }

    public labelToBitArray(): string[] {
        return uint8ArrayToBitArray(this.label);
    }

    public toBitArray(): string[] {
        return [String(this.selector)].concat(this.labelToBitArray());
    }

    public bitMult(bit: number) {
        if (bit !== 0 && bit !== 1) {
            throw new Error("Bit must be 0 or 1");
        }
        return new WireValue(
            bitArrayMult(bit, this.label),
            bit * this.selector,
        );
    }

    toString() {
        const hexLabel = Buffer.from(this.label).toString("hex");
        return `WireLabel(${this.selector}, ${hexLabel.slice(0, 7)})`;
    }
}

export function sampleOffset(numBytes: number): WireValue {
    const offset = WireValue.sample(numBytes);
    offset.selector = 1;
    return offset;
}
export function sampleOffsetViaBigInt(): WireValue {
    const offset = WireValue.sampleViaBigInt();
    offset.selector = 1;
    return offset;
}

export interface GarblingWireState {
    // Represents the state of a wire *during* garbling, when both the zero and one version must be kept
    [key: number]: WireValue;
}

export type WireTable = {
    // A table of all the wires in the circuit.
    // Combines with the gate descriptions to fully describe the circuit.
    [key: WireId]: {
        isInput: boolean;
        isOutput: boolean;
    };
};

export type GarblingWireTable = {
    // A table for all of the wire states one must remember *when garbling*
    [key: WireId]: GarblingWireState;
};

export type GarbledWireTable = {
    // The encrypted truth tables that are send to the evaluator
    [key: string]: WireValue;
};

export type EvaluationTable = {
    // The wire values that are filled in during evaluation
    [key: WireId]: WireValue;
};

abstract class Gate {
    // Could represent a single gate or an arbitrarily complex sub-circuit
    public id: bigint;
    constructor(idGen: IDGen) {
        this.id = idGen.next();
    }

    abstract garble(
        garblingTable: GarblingWireTable,
        garbledTable: GarbledWireTable,
        offset: WireValue,
        H: HashFunction,
    ): void;

    abstract eval(
        et: EvaluationTable,
        gt: GarbledWireTable,
        N: number,
        H: HashFunction,
    ): void;
}

export class NotGate extends Gate {
    public inId;
    public outId;

    constructor(idGen: IDGen, inId: WireId, outId: WireId) {
        super(idGen);
        this.inId = inId;
        this.outId = outId;
    }

    garble(garblingTable: GarblingWireTable) {
        // Swap the wire labels
        const wireState = garblingTable[this.inId];

        garblingTable[this.outId] = {
            0: wireState[1],
            1: wireState[0],
        };
    }

    // Eval just passes the input through
    eval(et: EvaluationTable) {
        et[this.outId] = et[this.inId];
    }
}

abstract class TwoInputGate extends Gate {
    // Our atomic gates: Ands and Xors
    public aId: WireId;
    public bId: WireId;
    public outId: WireId;

    constructor(idGen: IDGen, a: WireId, b: WireId, out: WireId) {
        super(idGen);
        this.aId = a;
        this.bId = b;
        this.outId = out;
    }
}

export class XorGate extends TwoInputGate {
    garble(
        garblingTable: GarblingWireTable,
        _: GarbledWireTable,
        offset: WireValue,
    ) {
        // Free-Xor
        const valueA0 = garblingTable[this.aId][0];
        const valueB0 = garblingTable[this.bId][0];

        const zeroValue = WireValue.xor(valueA0, valueB0);
        const oneValue = WireValue.xor(zeroValue, offset);

        garblingTable[this.outId] = {
            0: zeroValue,
            1: oneValue,
        };
    }

    eval(et: EvaluationTable) {
        et[this.outId] = WireValue.xor(et[this.aId], et[this.bId]);
    }
}

export function generatorHalfGate(
    hashA0: WireValue,
    hashA1: WireValue,
    pB: number,
    offset: WireValue,
): WireValue {
    return WireValue.xor(WireValue.xor(hashA0, hashA1), offset.bitMult(pB));
}

export function evaluatorHalfGate(
    hashB0: WireValue,
    hashB1: WireValue,
    a0: WireValue,
): WireValue {
    return WireValue.xor(WireValue.xor(hashB0, hashB1), a0);
}

export function calcWG0(
    hashA0: WireValue,
    pA: number,
    tG: WireValue,
): WireValue {
    return WireValue.xor(hashA0, tG.bitMult(pA));
}

export function calcWE0(
    hashB0: WireValue,
    pB: number,
    tE: WireValue,
    a0: WireValue,
): WireValue {
    return WireValue.xor(hashB0, WireValue.xor(tE, a0).bitMult(pB));
}

export class AndGate extends TwoInputGate {
    static truthTable = [
        [0, 0],
        [0, 1],
    ];

    gGateId: bigint;
    eGateId: bigint;

    constructor(idGen: IDGen, a: WireId, b: WireId, out: WireId) {
        super(idGen, a, b, out);
        this.gGateId = idGen.next();
        this.eGateId = idGen.next();
    }

    garble(
        garblingTable: GarblingWireTable,
        garbledTable: GarbledWireTable,
        offset: WireValue,
        H: HashFunction,
    ) {
        const stateA = garblingTable[this.aId];
        const stateB = garblingTable[this.bId];

        const pA = stateA[0].selector;
        const pB = stateB[0].selector;

        const hashA0 = H.hash([stateA[0].toHashable(), this.gGateId]);
        const hashA1 = H.hash([stateA[1].toHashable(), this.gGateId]);
        const hashB0 = H.hash([stateB[0].toHashable(), this.eGateId]);
        const hashB1 = H.hash([stateB[1].toHashable(), this.eGateId]);

        const tG = generatorHalfGate(hashA0, hashA1, pB, offset);
        const wG0 = calcWG0(hashA0, pA, tG);
        const tE = evaluatorHalfGate(hashB0, hashB1, stateA[0]);
        const wE0 = calcWE0(hashB0, pB, tE, stateA[0]);

        const w0 = WireValue.xor(wG0, wE0);
        const w1 = WireValue.xor(w0, offset);

        garblingTable[this.outId] = { 0: w0, 1: w1 };
        garbledTable[this.gGateId.toString()] = tG;
        garbledTable[this.eGateId.toString()] = tE;
    }

    eval(
        et: EvaluationTable,
        gt: GarbledWireTable,
        _N: number,
        H: HashFunction,
    ) {
        const tG = gt[this.gGateId.toString()];
        const tE = gt[this.eGateId.toString()];

        if (tG === undefined || tE === undefined) {
            throw new Error("Half gate undefined");
        } else {
            const valueA = et[this.aId];
            const valueB = et[this.bId];

            const sA = valueA.selector;
            const sB = valueB.selector;

            const wG = WireValue.xor(
                H.hash([valueA.toHashable(), this.gGateId]),
                tG.bitMult(sA),
            );

            const wE = WireValue.xor(
                H.hash([valueB.toHashable(), this.eGateId]),
                WireValue.xor(tE, valueA).bitMult(sB),
            );

            et[this.outId] = WireValue.xor(wG, wE);
        }
    }
}

export class Circuit extends Gate {
    gates: Gate[];

    outputWireId = BigInt("1869968394");

    constructor(idGen: IDGen, gates: Gate[]) {
        super(idGen);
        this.gates = gates;
    }

    garble(
        garblingTable: GarblingWireTable,
        garbledTable: GarbledWireTable,
        offset: WireValue,
        H: HashFunction,
    ) {
        this.gates.forEach((gate) =>
            gate.garble(garblingTable, garbledTable, offset, H),
        );
    }

    eval(
        et: EvaluationTable,
        gt: GarbledWireTable,
        N: number,
        H: HashFunction,
    ) {
        this.gates.forEach((gate) => gate.eval(et, gt, N, H));
    }
}

export class GarbledCircuit {
    // Garbled Truth table (filled out during garbling)
    garbledTable: GarbledWireTable = {};
    // Encrypted output values (filled out during garbling)
    outputTable: {
        [key: WireId]: Ciphertext[];
    } = {};
    // Gate descriptions
    circuit: Circuit;

    constructor(circuit: Circuit) {
        this.circuit = circuit;
    }

    eval(et: EvaluationTable, N: number, H: HashFunction): number[] {
        // Expect that et has the values for the input wires filled in.
        this.circuit.eval(et, this.garbledTable, N, H);

        return Object.keys(this.outputTable).map((id) => {
            const outputValue = et[id];
            const hash = H.hash([
                outputValue.toHashable(),
                this.circuit.outputWireId,
                BigInt(id),
            ]);

            return WireValue.xor(
                hash,
                this.outputTable[id][outputValue.selector],
            ).label[0];
        });
    }
}

export function garbleCircuit(
    circuit: Circuit,
    wireTable: WireTable,
    N: number,
    H: HashFunction,
): { garbledCircuit: GarbledCircuit; inputWireLabels: GarblingWireTable } {
    const gc = new GarbledCircuit(circuit);
    const offset = sampleOffset(N);

    const garblingTable: GarblingWireTable = {};
    const inputWireLabels: GarblingWireTable = {};

    // Sample values for input wires
    Object.keys(wireTable).forEach((id) => {
        const wire = wireTable[id];
        if (wire.isInput) {
            const zeroValue = WireValue.sample(N);
            const oneValue = WireValue.xor(zeroValue, offset);

            const wireState: GarblingWireState = {
                0: zeroValue,
                1: oneValue,
            };

            garblingTable[id] = wireState;
            inputWireLabels[id] = wireState;
        }
    });

    // Garble gates
    circuit.gates.forEach((gate) =>
        gate.garble(garblingTable, gc.garbledTable, offset, H),
    );

    // Set output wire values
    Object.keys(wireTable).forEach((id) => {
        const wire = wireTable[id];
        if (wire.isOutput) {
            gc.outputTable[id] = [];
            const garbledWire = garblingTable[id];

            for (let val = 0; val < 2; val++) {
                const hash = H.hash([
                    garbledWire[val].toHashable(),
                    circuit.outputWireId,
                    BigInt(id),
                ]);
                gc.outputTable[id][garbledWire[val].selector] = WireValue.xor(
                    hash,
                    new WireValue(new Uint8Array([val]), 0),
                );
            }
        }
    });
    return { garbledCircuit: gc, inputWireLabels: inputWireLabels };
}

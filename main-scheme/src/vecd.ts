import { Base8 } from "@zk-kit/baby-jubjub";

import { Bot, KeyPair } from "./pke";
import {
  MatchRevealPKE,
  ElGamalMatchReveal,
  RandomnessReuseElGamalMatchReveal as rregmr,
  Params,
  SecretKey,
  PublicKey,
  Alpha,
  RRRevealCiphertext,
  RRMatchCiphertext,
  RROTPCiphertext,
  isBot,
} from "./pke";
import { BJPoint, toBaseArray } from "./utils";

export type Ciphertext<RCT, MCT, OTPCT, AUX> = {
  first: [RCT, MCT];
  middle: [OTPCT, MCT][];
  last: OTPCT;
  aux: AUX;
};

interface VECDParams<P> {
  pke: P;
  n: number;
  b: number;
}

// TODO: Make thr a part of SK
interface VECD<P, PK, SK, M, A, RCT, MCT, OTPCT, R, AUX> {
  setup(n: number, b: number): VECDParams<P>;
  keyGen(params: VECDParams<P>, thr: number): KeyPair<PK[][], (SK | Bot)[][]>;
  conditionalEncryptReveal(
    params: VECDParams<P>,
    currentDigit: number,
    r: R,
    pkRow: PK[],
    m: M
  ): RCT;
  encryptDet(
    params: VECDParams<P>,
    pk: PK[][],
    baseArray: number[],
    m: M,
    alphas: A[],
    rs: R[][]
  ): Ciphertext<RCT, MCT, OTPCT, AUX>;
  encrypt(
    params: VECDParams<P>,
    pk: PK[][],
    t: number,
    m: M
  ): Ciphertext<RCT, MCT, OTPCT, AUX>;
  decrypt(
    params: VECDParams<P>,
    thr: number,
    sk: (SK | Bot)[][], // TODO: Replace with built-in option type
    ct: Ciphertext<RCT, MCT, OTPCT, AUX>
  ): M | Bot;
}

function unwrapSK<T>(sk: T | Bot): T {
  if (isBot(sk)) {
    throw new Error("Was Bot");
  } else {
    return sk;
  }
}

export function createVECD<P, PK, SK, M, A, RCT, MCT, OTPCT, R>(
  mrPKE: MatchRevealPKE<P, PK, SK, M, A, RCT, MCT, OTPCT, R, any>
): VECD<P, PK, SK, M, A, RCT, MCT, OTPCT, R, {}> {
  return {
    setup(n: number, b: number): VECDParams<P> {
      return {
        pke: mrPKE.setup(),
        n: n,
        b: b,
      };
    },

    keyGen(params, thr) {
      const baseArray = toBaseArray(params.n, thr, params.b);
      const pkTable: PK[][] = Array.from({ length: params.n }, () =>
        Array(params.b)
      );

      const skTable: (SK | Bot)[][] = Array.from({ length: params.n }, () =>
        Array(params.b)
      );

      for (let i = 0; i < params.n; i++) {
        for (let j = 0; j < params.b; j++) {
          if (j < baseArray[i]) {
            pkTable[i][j] = mrPKE.keyGenLossy(params.pke);
            skTable[i][j] = {};
          } else {
            const keypair = mrPKE.keyGen(params.pke);
            pkTable[i][j] = keypair.pk;
            skTable[i][j] = keypair.sk;
          }
        }
      }

      return {
        pk: pkTable,
        sk: skTable,
      };
    },

    encrypt(params, pk, t, m) {
      const alphas: A[] = Array.from({ length: params.n - 1 }, () =>
        mrPKE.sampleMask()
      );
      const rs = [
        Array.from({ length: params.n }, () => mrPKE.sampleR()),
        Array.from({ length: params.n - 1 }, () => mrPKE.sampleR()),
      ];
      return this.encryptDet(
        params,
        pk,
        toBaseArray(params.n, t, params.b),
        m,
        alphas,
        rs
      );
    },

    conditionalEncryptReveal(params, currentDigit, r, pkRow, m) {
      return mrPKE.encRevealDet(params.pke, pkRow[currentDigit], m, r);
    },

    encryptDet(params, pk, baseArray, m, alphas, rs) {
      const ctR0 = this.conditionalEncryptReveal(
        params,
        baseArray[0],
        rs[0][0],
        pk[0],
        m
      );
      const ctM0 = mrPKE.encMatchDet(
        params.pke,
        pk[0][baseArray[0] + 1],
        alphas[0],
        rs[1][0]
      );

      const middle: [OTPCT, MCT][] = [];
      for (let i = 1; i < params.n - 1; i++) {
        const betaMi = this.conditionalEncryptReveal(
          params,
          baseArray[i],
          rs[0][i],
          pk[i],
          m
        );
        const ctRi = mrPKE.otpEncCiphertext(alphas[i - 1], betaMi);

        const betaI = mrPKE.otpEncMask(alphas[i - 1], alphas[i]);
        const ctMi = mrPKE.encMatchDet(
          params.pke,
          pk[i][baseArray[i]],
          betaI,
          rs[1][i]
        );
        middle.push([ctRi, ctMi]);
      }

      const betaMFinal = this.conditionalEncryptReveal(
        params,
        baseArray[params.n - 1],
        rs[0][params.n - 1],
        pk[params.n - 1],
        m
      );

      const ctRFinal = mrPKE.otpEncCiphertext(alphas[params.n - 2], betaMFinal);

      return {
        first: [ctR0, ctM0],
        middle,
        last: ctRFinal,
        aux: {},
      };
    },

    decrypt(params, thr, sk, ct) {
      const baseArray = toBaseArray(params.n, thr, params.b);
      const alphas: A[] = [];

      const tryKeys = (i: number, ct: RCT): M | Bot => {
        for (let j = baseArray[i]; j < params.b; j++) {
          const currentSK = unwrapSK(sk[i][j]);
          if (mrPKE.detKey(currentSK, ct)) {
            return mrPKE.decReveal(currentSK, ct);
          }
        }
        return {};
      };

      const firstResult = tryKeys(0, ct.first[0]);
      if (!isBot(firstResult)) {
        return firstResult;
      }

      alphas.push(mrPKE.decMatch(unwrapSK(sk[0][baseArray[0]]), ct.first[1]));

      for (let i = 1; i < params.n - 1; i++) {
        const betaMJ = mrPKE.otpDecCiphertext(
          alphas[i - 1],
          ct.middle[i - 1][0]
        );

        const res = tryKeys(i, betaMJ);
        if (!isBot(res)) {
          return res;
        }

        const betaIm1 = mrPKE.decMatch(
          unwrapSK(sk[i][baseArray[i]]),
          ct.middle[i - 1][1]
        );
        alphas.push(mrPKE.otpDecMask(alphas[i - 1], betaIm1));
      }

      const betaMJ = mrPKE.otpDecCiphertext(alphas[params.n - 2], ct.last);
      return tryKeys(params.n - 1, betaMJ);
    },
  };
}

const mrVECD = createVECD(ElGamalMatchReveal);
interface rrAux {
  reveal: bigint;
  match: bigint;
}
export const rrVECD: VECD<
  Params,
  PublicKey,
  SecretKey,
  BJPoint,
  Alpha,
  RRRevealCiphertext,
  RRMatchCiphertext,
  RROTPCiphertext,
  bigint,
  rrAux
> = {
  setup: mrVECD.setup,
  keyGen: mrVECD.keyGen,
  encrypt() {
    throw Error("Not implemented");
  },
  conditionalEncryptReveal(params, currentDigit, r, pkRow, m) {
    if (currentDigit == 0) {
      return rregmr.encRevealDet(params.pke, pkRow[0], Base8, r);
    } else {
      return rregmr.encRevealDet(params.pke, pkRow[currentDigit - 1], m, r);
    }
  },
  encryptDet(params, pk, baseArray, m, alphas, rs) {
    const ctR0 = this.conditionalEncryptReveal(
      params,
      baseArray[0],
      rs[0][0],
      pk[0],
      m
    );
    const ctM0 = rregmr.encMatchDet(
      params.pke,
      pk[0][baseArray[0]],
      alphas[0],
      rs[1][0]
    );

    const middle: [RROTPCiphertext, RRMatchCiphertext][] = [];
    for (let i = 1; i < params.n - 1; i++) {
      const betaMi = this.conditionalEncryptReveal(
        params,
        baseArray[i],
        rs[0][0],
        pk[i],
        m
      );
      const ctRi = rregmr.otpEncCiphertext(alphas[i - 1], betaMi);
      const betaI = rregmr.otpEncMask(alphas[i - 1], alphas[i]);
      const ctMi = rregmr.encMatchDet(
        params.pke,
        pk[i][baseArray[i]],
        betaI,
        rs[1][0]
      );
      middle.push([ctRi, ctMi]);
    }

    const betaMFinal = this.conditionalEncryptReveal(
      params,
      baseArray[params.n - 1],
      rs[0][0],
      pk[params.n - 1],
      m
    );
    const ctRFinal = rregmr.otpEncCiphertext(alphas[params.n - 2], betaMFinal);
    return {
      first: [ctR0, ctM0],
      middle,
      last: ctRFinal,
      aux: { reveal: rs[0][0], match: rs[1][0] },
    };
  },

  decrypt(params, thr, sk, ct) {
    const baseArray = toBaseArray(params.n, thr, params.b);
    const alphas: Alpha[] = [];

    const tryKeys = (i: number, rct: RRRevealCiphertext): BJPoint | Bot => {
      for (let j = baseArray[i]; j < params.b; j++) {
        const currentSK = unwrapSK(sk[i][j]);
        if (rregmr.detKey(currentSK, rct, ct.aux.reveal)) {
          return rregmr.decReveal(currentSK, rct, ct.aux.reveal);
        }
      }
      return {};
    };

    const firstResult = tryKeys(0, ct.first[0]);
    if (!isBot(firstResult)) {
      return firstResult;
    }
    alphas.push(
      rregmr.decMatch(unwrapSK(sk[0][baseArray[0]]), ct.first[1], ct.aux.match)
    );

    for (let i = 1; i < params.n - 1; i++) {
      const betaMJ = rregmr.otpDecCiphertext(
        alphas[i - 1],
        ct.middle[i - 1][0]
      );
      const res = tryKeys(i, betaMJ);
      if (!isBot(res)) {
        return res;
      }
      const betaIm1 = rregmr.decMatch(
        unwrapSK(sk[i][baseArray[i]]),
        ct.middle[i - 1][1],
        ct.aux.match
      );
      alphas.push(rregmr.otpDecMask(alphas[i - 1], betaIm1));
    }

    const betaMJ = rregmr.otpDecCiphertext(alphas[params.n - 2], ct.last);
    return tryKeys(params.n - 1, betaMJ);
  },
};

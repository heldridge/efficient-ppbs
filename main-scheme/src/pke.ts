import { mulPointEscalar, Base8, order, addPoint } from "@zk-kit/baby-jubjub";

import {
  babyJubEqual,
  babyJubSubtract,
  BJPoint,
  genRandomBabyJubPoint,
  genRandomBabyJubScalar,
} from "./utils";
import { egDecrypt, egEncrypt, egKeyGen, EGCiphertext } from "./elgamal";

export type Bot = {};
export function isBot(obj: any): obj is {} {
  return (
    typeof obj === "object" && obj !== null && Object.keys(obj).length === 0
  );
}

export interface MatchRevealPKE<P, PK, SK, M, A, RCT, MCT, OTPCT, R, AUX> {
  setup(): P;
  keyGen(params: P): KeyPair<PK, SK>;
  keyGenLossy(params: P): PK;
  encRevealDet(params: P, pk: PK, msg: M, r: R): RCT;
  encReveal(params: P, pk: PK, msg: M): RCT;
  encMatchDet(params: P, pk: PK, mask: A, r: R): MCT;
  encMatch(params: P, pk: PK, mask: A): MCT;
  otpEncCiphertext(mask: A, ct: RCT): OTPCT;
  otpEncMask(maskA: A, maskB: A): A;
  sampleMask(): A;
  decReveal(sk: SK, ct: RCT, aux?: AUX): M | Bot;
  decMatch(sk: SK, ct: MCT, aux?: AUX): A;
  otpDecCiphertext(mask: A, ct: OTPCT): RCT;
  otpDecMask(maskA: A, maskB: A): A;
  detKey(sk: SK, ct: RCT, aux?: AUX): boolean;
  sampleR(): R;
}

export interface Params {
  q: bigint;
  g: BJPoint;
  h: BJPoint;
}

export interface KeyPair<PK, SK> {
  pk: PK;
  sk: SK;
}

export interface PublicKey {
  X: BJPoint;
  XBar: BJPoint;
}

export interface SecretKey {
  x: bigint;
  xBar: bigint;
}

export type Alpha = [BJPoint, BJPoint];

export interface RevealCiphertext {
  R: BJPoint;
  CBar: BJPoint;
  C: BJPoint;
}

export interface MatchCiphertext {
  R: BJPoint;
  alpha0: BJPoint;
  alpha1: BJPoint;
}

export interface OTPCiphertext {
  R: BJPoint;
  aCBar: BJPoint;
  aC: BJPoint;
}

export type MaskCiphertext = Alpha;

export const ElGamalMatchReveal: MatchRevealPKE<
  Params,
  PublicKey,
  SecretKey,
  BJPoint,
  Alpha,
  RevealCiphertext,
  MatchCiphertext,
  OTPCiphertext,
  bigint,
  {}
> = {
  setup(): Params {
    const h = mulPointEscalar(Base8, genRandomBabyJubScalar());

    return {
      q: order,
      g: Base8,
      h,
    };
  },

  keyGen(params: Params): KeyPair<PublicKey, SecretKey> {
    const regular = egKeyGen(params.g);
    const bar = egKeyGen(params.g);

    return {
      pk: {
        X: regular.pk,
        XBar: bar.pk,
      },
      sk: {
        x: regular.sk,
        xBar: bar.sk,
      },
    };
  },

  keyGenLossy(params: Params): PublicKey {
    const regular = egKeyGen(params.h);
    const bar = egKeyGen(params.h);

    return {
      X: regular.pk,
      XBar: bar.pk,
    };
  },

  encRevealDet(
    params: Params,
    pk: PublicKey,
    msg: BJPoint,
    r: bigint,
  ): RevealCiphertext {
    const ct = egEncrypt(params.g, pk.X, r, msg);
    const CBar = mulPointEscalar(pk.XBar, r);

    return {
      ...ct,
      CBar,
    };
  },

  encReveal(params, pk, msg) {
    const r = genRandomBabyJubScalar();
    return this.encRevealDet(params, pk, msg, r);
  },

  encMatchDet(
    params: Params,
    pk: PublicKey,
    mask: Alpha,
    r: bigint,
  ): MatchCiphertext {
    const ct0 = egEncrypt(params.g, pk.XBar, r, mask[0]);
    const ct1 = egEncrypt(params.g, pk.X, r, mask[1]);

    return {
      R: ct0.R,
      alpha0: ct0.C,
      alpha1: ct1.C,
    };
  },

  encMatch(params, pk, mask) {
    const r = genRandomBabyJubScalar();
    return this.encMatchDet(params, pk, mask, r);
  },

  otpEncCiphertext(mask: Alpha, ct: RevealCiphertext): OTPCiphertext {
    return {
      R: ct.R,
      aCBar: addPoint(mask[0], ct.CBar),
      aC: addPoint(mask[1], ct.C),
    };
  },

  otpEncMask(maskA: Alpha, maskB: Alpha): Alpha {
    return [addPoint(maskA[0], maskB[0]), addPoint(maskA[1], maskB[1])];
  },

  sampleMask(): Alpha {
    return [genRandomBabyJubPoint(), genRandomBabyJubPoint()];
  },

  detKey(sk, ct) {
    return babyJubEqual(mulPointEscalar(ct.R, sk.xBar), ct.CBar);
  },

  decReveal(sk, ct) {
    if (this.detKey(sk, ct)) {
      return egDecrypt(sk.x, new EGCiphertext(ct.R, ct.C));
    } else {
      return {};
    }
  },

  decMatch(sk, ct) {
    return [
      egDecrypt(sk.xBar, new EGCiphertext(ct.R, ct.alpha0)),
      egDecrypt(sk.x, new EGCiphertext(ct.R, ct.alpha1)),
    ];
  },

  otpDecCiphertext(mask, ct) {
    return {
      R: ct.R,
      CBar: babyJubSubtract(mask[0], ct.aCBar),
      C: babyJubSubtract(mask[1], ct.aC),
    };
  },

  otpDecMask(maskA, maskB) {
    return [
      babyJubSubtract(maskA[0], maskB[0]),
      babyJubSubtract(maskA[1], maskB[1]),
    ];
  },

  sampleR() {
    return genRandomBabyJubScalar();
  },
};

function unwrap<T>(val: T | undefined): T {
  if (val === undefined) {
    throw Error("Unwrapping an undefined value");
  } else {
    return val;
  }
}

export interface RRRevealCiphertext {
  CBar: BJPoint;
  C: BJPoint;
}
export interface RRMatchCiphertext {
  alpha0: BJPoint;
  alpha1: BJPoint;
}
export interface RROTPCiphertext {
  aCBar: BJPoint;
  aC: BJPoint;
}

export const RandomnessReuseElGamalMatchReveal: MatchRevealPKE<
  Params,
  PublicKey,
  SecretKey,
  BJPoint,
  Alpha,
  RRRevealCiphertext,
  RRMatchCiphertext,
  RROTPCiphertext,
  bigint,
  bigint
> = {
  ...ElGamalMatchReveal,

  encRevealDet(params, pk, msg, r): RRRevealCiphertext {
    const ct = ElGamalMatchReveal.encRevealDet(params, pk, msg, r);
    return {
      C: ct.C,
      CBar: ct.CBar,
    };
  },

  encMatchDet(params, pk, mask, r): RRMatchCiphertext {
    const ct = ElGamalMatchReveal.encMatchDet(params, pk, mask, r);
    return {
      alpha0: ct.alpha0,
      alpha1: ct.alpha1,
    };
  },

  otpEncCiphertext(mask: Alpha, ct: RevealCiphertext): RROTPCiphertext {
    const newCt = ElGamalMatchReveal.otpEncCiphertext(mask, ct);
    return {
      aCBar: newCt.aCBar,
      aC: newCt.aC,
    };
  },

  detKey(sk, ct, aux) {
    const R = mulPointEscalar(Base8, unwrap(aux));
    return ElGamalMatchReveal.detKey(sk, { ...ct, R });
  },

  decReveal(sk, ct, aux: bigint) {
    const R = mulPointEscalar(Base8, unwrap(aux));
    return ElGamalMatchReveal.decReveal(sk, { ...ct, R });
  },

  decMatch(sk, ct, aux: bigint) {
    const R = mulPointEscalar(Base8, unwrap(aux));
    return ElGamalMatchReveal.decMatch(sk, { ...ct, R });
  },

  otpDecCiphertext(mask, ct) {
    return {
      CBar: babyJubSubtract(mask[0], ct.aCBar),
      C: babyJubSubtract(mask[1], ct.aC),
    };
  },

  sampleR() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);

    let result = BigInt(0);
    for (const byte of bytes) {
      result = (result << BigInt(8)) | BigInt(byte);
    }
    const mask = (BigInt(1) << BigInt(253)) - BigInt(1);

    return result & mask;
  },
};

import { addPoint, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { babyJubInverse, BJPoint, genRandomBabyJubScalar } from "./utils";
import { KeyPair } from "./pke";

export class EGCiphertext {
  R: BJPoint;
  C: BJPoint;

  constructor(R: BJPoint, C: BJPoint) {
    this.R = R;
    this.C = C;
  }

  flatten(): BigInt[] {
    return [this.R, this.C].flat();
  }
}

export function egKeyGen(g: BJPoint): KeyPair<BJPoint, bigint> {
  const sk = genRandomBabyJubScalar();
  const pk = mulPointEscalar(g, sk);

  return {
    sk,
    pk,
  };
}

export function egEncrypt(
  g: BJPoint,
  pk: BJPoint,
  r: bigint,
  m: BJPoint
): EGCiphertext {
  const R = mulPointEscalar(g, r);
  const C = addPoint(mulPointEscalar(pk, r), m);

  return new EGCiphertext(R, C);
}

export function egDecrypt(sk: bigint, ct: EGCiphertext): BJPoint {
  const T = mulPointEscalar(ct.R, sk);
  return addPoint(ct.C, babyJubInverse(T));
}

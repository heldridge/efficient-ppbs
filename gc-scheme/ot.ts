import { PrivKey, PubKey, genPrivKey, genPubKey } from "maci-crypto";
import {
  ElGamalCiphertext,
  decrypt,
  BabyJubPoint,
  encryptEncoded,
  Message,
} from "./elgamal-babyjub";

export type SenderInput = [Message, Message];
export type ReceiverMessage = [PubKey, PubKey];
export type SenderMessage = [ElGamalCiphertext, ElGamalCiphertext];

interface ReceiverState {
  pubKeys: ReceiverMessage;
  privKey: PrivKey;
  choice: number;
}

// TODO: Require that R be a 253 int
export function senderMessage(
  senderInput: SenderInput,
  receiverMessage: ReceiverMessage,
  r: bigint,
): SenderMessage {
  return senderInput.map((pt, index) =>
    encryptEncoded(pt, receiverMessage[index], r),
  ) as SenderMessage;
}

export function receiverMessage(choice: number): ReceiverState {
  const privKey = genPrivKey();
  const realPubkey = genPubKey(privKey);
  const fakePubkey = genPubKey(genPrivKey());
  const pubKeys = Array(2);
  pubKeys[choice] = realPubkey;
  pubKeys[1 - choice] = fakePubkey;

  return {
    pubKeys: pubKeys as [PubKey, PubKey],
    privKey,
    choice,
  };
}

export function receiverEval(
  state: ReceiverState,
  senderMessage: SenderMessage,
): bigint {
  const msg = senderMessage[state.choice];
  // Cast as bigint here because library uses a strange ts interface
  const decrypted = decrypt(state.privKey, msg) as bigint;
  return decrypted;
}

export function multiSenderMessage(
  senderInputs: SenderInput[],
  receiverMessages: ReceiverMessage[],
  r: bigint,
): SenderMessage[] {
  return senderInputs.map((senderInput, index) => {
    return senderMessage(senderInput, receiverMessages[index], r);
  });
}

export function multiReceiverMessage(choices: number[]): ReceiverState[] {
  return choices.map((choice) => receiverMessage(choice));
}

export function multiReceiverEval(
  states: ReceiverState[],
  senderMessages: SenderMessage[],
): bigint[] {
  return senderMessages.map((senderMessage, index) => {
    return receiverEval(states[index], senderMessage);
  });
}

import { initAlice, initBob, ratchetDecrypt, ratchetEncrypt } from '../double-ratchet/core';
import { defaultRatchetDependencies, wipeRatchetState } from '../double-ratchet/state';
import type { DoubleRatchetState, RatchetDependencies } from '../double-ratchet/types';
import { initiatePqXdh, respondPqXdh } from '../pqxdh/core';
import type {
  PqXdhInitiatorDependencies,
  PqXdhPublicBundle,
  PqXdhResponderDependencies,
  PqXdhResponderPrivateBundle,
  X25519KeyPair,
} from '../pqxdh/types';
import { wipe } from '../primitives';
import { sessionMessageAad } from './aad';
import { decodeSessionMessageHeader, encodeSessionMessageHeader } from './wire';

export type InitiatePrekeyMessageInput = {
  sessionId: string;
  initiatorIdentity: X25519KeyPair;
  recipientBundle: PqXdhPublicBundle;
  plaintext: Uint8Array;
  conversationAad: Uint8Array;
  pqxdhDependencies?: PqXdhInitiatorDependencies;
  ratchetDependencies?: RatchetDependencies;
};

export type InitiatedPrekeyMessage = {
  sessionId: string;
  state: DoubleRatchetState;
  pqxdhAssociatedData: Uint8Array;
  header: string;
  ciphertext: Uint8Array;
};

export type OpenPrekeyMessageInput = {
  header: string;
  ciphertext: Uint8Array;
  responderBundle: PqXdhResponderPrivateBundle;
  conversationAad: Uint8Array;
  pqxdhDependencies?: PqXdhResponderDependencies;
  ratchetDependencies?: RatchetDependencies;
};

export type OpenedPrekeyMessage = {
  sessionId: string;
  state: DoubleRatchetState;
  pqxdhAssociatedData: Uint8Array;
  plaintext: Uint8Array;
  usedEcOneTimePrekeyId: string | null;
  usedPqOneTimePrekeyId: string | null;
};

export async function initiatePrekeyMessage(input: InitiatePrekeyMessageInput): Promise<InitiatedPrekeyMessage> {
  const pqxdh = input.pqxdhDependencies
    ? await initiatePqXdh(input.initiatorIdentity, input.recipientBundle, input.pqxdhDependencies)
    : await initiatePqXdh(input.initiatorIdentity, input.recipientBundle);
  const ratchetDependencies = input.ratchetDependencies ?? defaultRatchetDependencies();
  let initialState: DoubleRatchetState | undefined;
  try {
    initialState = initAlice(pqxdh.sharedSecret, input.recipientBundle.signedPrekey.publicKey, ratchetDependencies);
    const aad = sessionMessageAad(input.conversationAad, pqxdh.associatedData, input.sessionId);
    const encrypted = ratchetEncrypt(initialState, input.plaintext, aad, ratchetDependencies);
    return {
      sessionId: input.sessionId,
      state: encrypted.state,
      pqxdhAssociatedData: pqxdh.associatedData.slice(),
      header: encodeSessionMessageHeader({
        protocol: 'secure-messaging',
        version: 1,
        kind: 'prekey',
        sessionId: input.sessionId,
        pqxdh: pqxdh.header,
        ratchet: encrypted.message.header,
      }),
      ciphertext: encrypted.message.ciphertext,
    };
  } finally {
    wipe(pqxdh.sharedSecret);
    if (initialState) wipeRatchetState(initialState);
  }
}

export function openPrekeyMessage(input: OpenPrekeyMessageInput): OpenedPrekeyMessage {
  const header = decodeSessionMessageHeader(input.header);
  if (header.kind !== 'prekey') throw new Error('Expected a prekey session message');
  const pqxdh = input.pqxdhDependencies
    ? respondPqXdh(header.pqxdh, input.responderBundle, input.pqxdhDependencies)
    : respondPqXdh(header.pqxdh, input.responderBundle);
  const ratchetDependencies = input.ratchetDependencies ?? defaultRatchetDependencies();
  let initialState: DoubleRatchetState | undefined;
  try {
    initialState = initBob(pqxdh.sharedSecret, input.responderBundle.signedPrekey);
    const aad = sessionMessageAad(input.conversationAad, pqxdh.associatedData, header.sessionId);
    const decrypted = ratchetDecrypt(
      initialState,
      { header: header.ratchet, ciphertext: input.ciphertext },
      aad,
      ratchetDependencies,
    );
    return {
      sessionId: header.sessionId,
      state: decrypted.state,
      pqxdhAssociatedData: pqxdh.associatedData.slice(),
      plaintext: decrypted.plaintext,
      usedEcOneTimePrekeyId: pqxdh.usedEcOneTimePrekeyId,
      usedPqOneTimePrekeyId: pqxdh.usedPqOneTimePrekeyId,
    };
  } finally {
    wipe(pqxdh.sharedSecret);
    if (initialState) wipeRatchetState(initialState);
  }
}

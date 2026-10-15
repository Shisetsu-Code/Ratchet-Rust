export type DhKeyPair = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export type RatchetHeader = {
  dh: Uint8Array;
  pn: number;
  n: number;
};

export type RatchetCiphertext = {
  header: RatchetHeader;
  ciphertext: Uint8Array;
};

export type SkippedMessageKey = {
  dh: Uint8Array;
  n: number;
  messageKey: Uint8Array;
};

export type DoubleRatchetState = {
  dhs: DhKeyPair;
  dhr: Uint8Array | null;
  rk: Uint8Array;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number;
  nr: number;
  pn: number;
  skipped: SkippedMessageKey[];
};

export type RatchetDependencies = {
  generateDh: () => DhKeyPair;
  nonce: () => Uint8Array;
};

export type RatchetEncryptResult = {
  state: DoubleRatchetState;
  message: RatchetCiphertext;
};

export type RatchetDecryptResult = {
  state: DoubleRatchetState;
  plaintext: Uint8Array;
};

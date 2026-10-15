export type X25519KeyPair = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export type SignedEcPrekeyPublic = {
  prekeyId: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
};

export type SignedPqPrekeyPublic = {
  prekeyId: string;
  publicKey: Uint8Array;
  signature: Uint8Array;
  kind: 'ONE_TIME' | 'LAST_RESORT';
};

export type EcOneTimePrekeyPublic = {
  prekeyId: string;
  publicKey: Uint8Array;
};

export type PqXdhPublicBundle = {
  identityPublicKey: Uint8Array;
  signedPrekey: SignedEcPrekeyPublic;
  pqPrekey: SignedPqPrekeyPublic;
  ecOneTimePrekey: EcOneTimePrekeyPublic | null;
};

export type PqXdhInitiationHeader = {
  identityPublicKey: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  kemCiphertext: Uint8Array;
  signedPrekeyId: string;
  pqPrekeyId: string;
  pqPrekeyKind: 'ONE_TIME' | 'LAST_RESORT';
  ecOneTimePrekeyId: string | null;
};

export type PqXdhInitiatorResult = {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
  header: PqXdhInitiationHeader;
};

export type PqXdhResponderPrivateBundle = {
  identityKeyPair: X25519KeyPair;
  signedPrekey: X25519KeyPair & { prekeyId: string };
  pqPrekey: { prekeyId: string; secretKey: Uint8Array; kind: 'ONE_TIME' | 'LAST_RESORT' };
  ecOneTimePrekey: (X25519KeyPair & { prekeyId: string }) | null;
};

export type PqXdhResponderResult = {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
  usedEcOneTimePrekeyId: string | null;
  usedPqOneTimePrekeyId: string | null;
};

export type PqXdhInitiatorDependencies = {
  verifySignature: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => Promise<boolean>;
  generateEphemeral: () => X25519KeyPair;
  encapsulate: (publicKey: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
};

export type PqXdhResponderDependencies = {
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

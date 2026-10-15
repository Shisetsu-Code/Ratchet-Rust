import { concatBytes } from './encoding';
import {
  CHAIN_MESSAGE_CONSTANT_V1,
  CHAIN_NEXT_CONSTANT_V1,
  CRYPTO_PROFILE_V1,
  RATCHET_ROOT_INFO_V1,
} from './profile';
import { hkdfSha256, hmacSha256 } from './primitives';

export type RootKdfOutput = { rootKey: Uint8Array; chainKey: Uint8Array };
export type ChainKdfOutput = { messageKey: Uint8Array; nextChainKey: Uint8Array };

export function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): RootKdfOutput {
  require32(rootKey, 'root key');
  require32(dhOutput, 'DH output');
  const material = hkdfSha256(
    dhOutput,
    rootKey,
    RATCHET_ROOT_INFO_V1,
    CRYPTO_PROFILE_V1.messageKeyLength * 2,
  );
  return {
    rootKey: material.slice(0, 32),
    chainKey: material.slice(32, 64),
  };
}

export function kdfChain(chainKey: Uint8Array): ChainKdfOutput {
  require32(chainKey, 'chain key');
  return {
    messageKey: hmacSha256(chainKey, CHAIN_MESSAGE_CONSTANT_V1),
    nextChainKey: hmacSha256(chainKey, CHAIN_NEXT_CONSTANT_V1),
  };
}

export function messageAad(...parts: readonly Uint8Array[]): Uint8Array {
  return concatBytes(...parts);
}

function require32(value: Uint8Array, label: string): void {
  if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
}

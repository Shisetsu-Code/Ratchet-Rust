import initWasm, {
  crypto_wasm_profile,
  xed25519_sign,
  xed25519_verify,
} from './wasm/generated/ratchet_crypto_wasm.js';
import { wipe } from './primitives';

const EXPECTED_WASM_PROFILE = 'ratchet-crypto-wasm/xed25519/v1';
const X25519_KEY_LENGTH = 32;
const XED25519_SIGNATURE_LENGTH = 64;
const XED25519_RANDOMNESS_LENGTH = 64;

let initialization: Promise<void> | null = null;

export class XEdDsaError extends Error {}

export async function xed25519Sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  requireLength(privateKey, X25519_KEY_LENGTH, 'XEd25519 private key');
  await ensureWasmReady();

  const privateCopy = privateKey.slice();
  const randomness = crypto.getRandomValues(new Uint8Array(XED25519_RANDOMNESS_LENGTH));
  try {
    const signature = xed25519_sign(privateCopy, message, randomness);
    requireLength(signature, XED25519_SIGNATURE_LENGTH, 'XEd25519 signature');
    return signature.slice();
  } catch (error) {
    throw new XEdDsaError(`XEd25519 signing failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  } finally {
    wipe(privateCopy, randomness);
  }
}

export async function xed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== X25519_KEY_LENGTH || signature.length !== XED25519_SIGNATURE_LENGTH) return false;
  await ensureWasmReady();
  return xed25519_verify(publicKey, message, signature);
}

export async function ensureXEdDsaReady(): Promise<void> {
  await ensureWasmReady();
}

async function ensureWasmReady(): Promise<void> {
  if (!initialization) {
    initialization = (async () => {
      await initWasm();
      const profile = crypto_wasm_profile();
      if (profile !== EXPECTED_WASM_PROFILE) {
        throw new XEdDsaError(`Unexpected XEd25519 WASM profile: ${profile}`);
      }
    })();
  }
  try {
    await initialization;
  } catch (error) {
    initialization = null;
    if (error instanceof XEdDsaError) throw error;
    throw new XEdDsaError(`XEd25519 WASM initialization failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

function requireLength(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) throw new XEdDsaError(`${label} must be ${expected} bytes`);
}

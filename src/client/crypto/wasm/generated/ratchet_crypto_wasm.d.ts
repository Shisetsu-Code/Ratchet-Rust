/* tslint:disable */
/* eslint-disable */

/**
 * Returns the explicit cryptographic profile implemented by this WASM module.
 */
export function crypto_wasm_profile(): string;

/**
 * Signs `message` with an `X25519`-format private key using `XEd25519`.
 *
 * # Errors
 *
 * Returns a JavaScript error when the private key is not 32 bytes, randomness
 * is not exactly 64 bytes, or the pinned signer consumes an unexpected amount
 * of randomness.
 */
export function xed25519_sign(private_key: Uint8Array, message: Uint8Array, randomness: Uint8Array): Uint8Array;

/**
 * Verifies an `XEd25519` signature against an `X25519`-format public key.
 */
export function xed25519_verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly crypto_wasm_profile: () => [number, number];
    readonly xed25519_sign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly xed25519_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

import type { ConsumePrekeyResponse } from '../../../shared/contracts/prekeys';
import type { PqXdhPublicBundle } from '../pqxdh/types';
import { base64UrlToBytes } from '../local-state/base64url';

export function consumedPrekeysToPqXdhBundle(response: ConsumePrekeyResponse): PqXdhPublicBundle {
  const pqOneTime = response.pq_one_time_prekey;
  if (pqOneTime && !pqOneTime.signature) throw new Error('Consumed PQ one-time prekey is missing its XEdDSA signature');
  return {
    identityPublicKey: base64UrlToBytes(response.bundle.identity_public_key),
    signedPrekey: {
      prekeyId: response.bundle.signed_prekey.prekey_id,
      publicKey: base64UrlToBytes(response.bundle.signed_prekey.public_key),
      signature: base64UrlToBytes(response.bundle.signed_prekey.signature),
    },
    pqPrekey: pqOneTime
      ? {
          prekeyId: pqOneTime.prekey_id,
          publicKey: base64UrlToBytes(pqOneTime.public_key),
          signature: base64UrlToBytes(pqOneTime.signature!),
          kind: 'ONE_TIME',
        }
      : {
          prekeyId: response.bundle.pq_last_resort_prekey.prekey_id,
          publicKey: base64UrlToBytes(response.bundle.pq_last_resort_prekey.public_key),
          signature: base64UrlToBytes(response.bundle.pq_last_resort_prekey.signature),
          kind: 'LAST_RESORT',
        },
    ecOneTimePrekey: response.ec_one_time_prekey
      ? {
          prekeyId: response.ec_one_time_prekey.prekey_id,
          publicKey: base64UrlToBytes(response.ec_one_time_prekey.public_key),
        }
      : null,
  };
}

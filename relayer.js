/**
 * Server-side Relayer wrapper
 * - Initialize createInstance using SepoliaConfig or a custom config.
 * - Provide two exported helpers with clear comments:
 *    - verifyEncryptedInput(contractAddress, externalInput, proof) => boolean
 *    - requestDecryption(contractAddress, ciphertext, requester) => { cleartext }
 *
 * IMPORTANT: actual method names differ across @zama-fhe/relayer-sdk releases.
 * Replace calls below with the exact SDK methods after checking your installed SDK.
 */

import { createInstance, SepoliaConfig } from '@zama-fhe/relayer-sdk';

let instance = null;
let initError = null;

export async function initRelayer() {
  if (instance || initError) return { instance, initError };
  try {
    instance = await createInstance(SepoliaConfig);
    console.log('Relayer SDK initialized.');
    return { instance, initError: null };
  } catch (err) {
    console.warn('Relayer init error:', err?.message || err);
    initError = err;
    return { instance: null, initError: err };
  }
}

export async function verifyEncryptedInput(contractAddress, externalInput, proof) {
  // externalInput: object (handles) that the client produced
  // proof: the ZKPoK associated with the externalInput
  if (!instance) throw new Error('Relayer SDK not initialized');

  // Try several possible SDK method names; adapt to your SDK
  try {
    if (typeof instance.verifyEncryptedInput === 'function') {
      return await instance.verifyEncryptedInput({
        contractAddress,
        externalInput,
        proof
      });
    } else if (typeof instance.verifyInput === 'function') {
      return await instance.verifyInput(contractAddress, externalInput, proof);
    } else if (instance.relayer && typeof instance.relayer.verify === 'function') {
      return await instance.relayer.verify(contractAddress, externalInput, proof);
    } else {
      throw new Error('No verification method found on relayer instance; update relayer.js to match your SDK');
    }
  } catch (err) {
    console.error('verifyEncryptedInput error:', err);
    throw err;
  }
}

export async function requestDecryption(contractAddress, ciphertextHandles, requesterAddress) {
  if (!instance) throw new Error('Relayer SDK not initialized');

  // Example variant: instance.requestDecryption({ contractAddress, ciphertext, requester })
  try {
    if (typeof instance.requestDecryption === 'function') {
      return await instance.requestDecryption({
        contractAddress,
        ciphertext: ciphertextHandles,
        requesterAddress
      });
    } else if (instance.gateway && typeof instance.gateway.requestDecryption === 'function') {
      return await instance.gateway.requestDecryption(contractAddress, ciphertextHandles, requesterAddress);
    } else {
      throw new Error('No decryption request method on relayer instance; update relayer.js to match your SDK');
    }
  } catch (err) {
    console.error('requestDecryption error:', err);
    throw err;
  }
}
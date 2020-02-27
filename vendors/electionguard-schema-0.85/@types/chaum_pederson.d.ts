/* tslint:disable */
/**
 * This file was automatically generated by json-schema-to-typescript.
 * DO NOT MODIFY IT BY HAND. Instead, modify the source JSONSchema file,
 * and run json-schema-to-typescript to regenerate this file.
 */

/**
 * The one-time public key `a = gʳ`, where `r` is the randomly generated one-time public key.
 */
export type BigNaturalNumber = string | number;
/**
 * The encoding `b = gᵐ hʳ`, where `m` is the cleartext and `h` is the recipient public key being used for encryption.
 */
export type BigNaturalNumber1 = string | number;
/**
 * The challenge value `c` that is produced by hashing relevent parameters, including the original ElGamal message `(a,b)` and the zero message `(α, β)`.
 */
export type BigUint = string | number;
/**
 * The response `u = t + c r mod (p-1)` to the challenge `c`, where `r` is the one-time private key used to encrypt the original message and `t` is the one-time private key used to encrypt the zero message used in this proof.
 */
export type BigUint1 = string | number;

/**
 * A non-interactive zero-knowledge Chaum-Pederson proof shows that an ElGamal message `(a,b) = (gʳ, gᵐ hʳ)` is actually an encryption of zero (`m = 0`) without revealing the nonce `r` used to encode it. This can be used to show that two ElGamal messages encrypt the same message, by creating a Chaum-Pederson proof for their quotient `(a₁/a₂, b₁/b₂) = (gʳ¹⁻ʳ², gᵐ¹⁻ᵐ² hʳ¹⁻ʳ²)`.
 */
export interface ChaumPedersonProof {
  committment: ElGamalMessage;
  challenge: BigUint;
  response: BigUint1;
  [k: string]: any;
}
/**
 * An ElGamal message `(α, β)` encoding zero. This is useful because you can only combine two ciphertexts if they both encode zero, as in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = β bᶜ`. This acts as a committment to the one-time private key `t` used in this proof.
 */
export interface ElGamalMessage {
  public_key: BigNaturalNumber;
  ciphertext: BigNaturalNumber1;
  [k: string]: any;
}
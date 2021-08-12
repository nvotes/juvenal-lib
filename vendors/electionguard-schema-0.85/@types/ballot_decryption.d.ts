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
 * The decrypted message of the selection.
 */
export type BigNaturalNumber2 = string | number;
/**
 * The share of the decrypted message `M_i`.
 */
export type BigUint = string | number;
/**
 * The challenge value `c` that is produced by hashing relevent parameters, including the original ElGamal message `(a,b)` and the zero message `(α, β)`.
 */
export type BigUint1 = string | number;
/**
 * The response `u = t + c r mod (p-1)` to the challenge `c`, where `r` is the one-time private key used to encrypt the original message and `t` is the one-time private key used to encrypt the zero message used in this proof.
 */
export type BigUint2 = string | number;
/**
 * The actual fragment `M_{i,j}` which is trustee `j`'s piece of the missing trustee `i`'s share of a decryption.
 */
export type BigNaturalNumber3 = string | number;
/**
 * The LaGrange coefficient `w_{i,j}` used to compute the decryption share from the fragments.
 */
export type BigUint3 = string | number;

/**
 * A decryption of an encrypted ballot that was spoiled.
 */
export interface BallotDecryption {
  contests: [
    [SelectionDecryption, ...(SelectionDecryption)[]],
    ...([SelectionDecryption, ...(SelectionDecryption)[]])[]
  ];
  ballot_info: BallotInformation;
  [k: string]: any;
}
/**
 * The decryption of the selection, including the encrypted message, the decrypted message, the decryption shares, and the cleartext.
 */
export interface SelectionDecryption {
  encrypted_message: ElGamalMessage;
  decrypted_message: BigNaturalNumber2;
  /**
   * The decryption shares `M_i` used to compute the decryption `M`.
   */
  shares: [DecryptionShare, ...(DecryptionShare)[]];
  /**
   * The actual value encrypted, so either a zero or a one.
   */
  cleartext: number;
  [k: string]: any;
}
/**
 * The encrypted message of the selection (the one or zero).
 */
export interface ElGamalMessage {
  public_key: BigNaturalNumber;
  ciphertext: BigNaturalNumber1;
  [k: string]: any;
}
/**
 * A single trustee's share of a decryption of some encrypted message `(a, b)`. The encrypted message can be an encrypted tally or an encrypted ballot.
 */
export interface DecryptionShare {
  share: BigUint;
  proof: ChaumPedersenProof;
  /**
   * The `k` fragments used to reconstruct this decryption share, if this trustee was absent.
   */
  fragments?: {
    /**
     * The index of the trustee who produced this fragment.
     */
    trustee_index: number;
    fragment: BigNaturalNumber3;
    lagrange_coefficient: BigUint3;
    proof: ChaumPedersenProof1;
    [k: string]: any;
  }[];
  [k: string]: any;
}
/**
 * The proof that the share encodes the same value as the encrypted message.
 */
export interface ChaumPedersenProof {
  commitment: ElGamalMessage1;
  challenge: BigUint1;
  response: BigUint2;
  [k: string]: any;
}
/**
 * An ElGamal message `(α, β)` encoding zero. This is useful because you can only combine two ciphertexts if they both encode zero, as in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = β bᶜ`. This acts as a commitment to the one-time private key `t` used in this proof.
 */
export interface ElGamalMessage1 {
  public_key: BigNaturalNumber;
  ciphertext: BigNaturalNumber1;
  [k: string]: any;
}
/**
 * The proof that the fragment encodes the same values as the encrypted message
 */
export interface ChaumPedersenProof1 {
  commitment: ElGamalMessage1;
  challenge: BigUint1;
  response: BigUint2;
  [k: string]: any;
}
/**
 * Auxiliary information about a ballot other than the selections made by the voter.
 */
export interface BallotInformation {
  /**
   * Information about the device that encrypted the ballot
   */
  device_info: string;
  /**
   * The date the ballot was encrypted.
   */
  date: string;
  /**
   * The time the ballot was encrypted.
   */
  time: string;
  /**
   * The tracker code generated for this ballot.
   */
  tracker: string;
  [k: string]: any;
}
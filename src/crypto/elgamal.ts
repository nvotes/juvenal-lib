import { arithm } from "../../vendors/vjsc/vjsc-1.1.1"

/**
 * Combines multiple public keys into a single shared public key.
 */
export function createJointPublicKey(
    publicKeys: arithm.ModPGroupElement[],
    group: arithm.ModPGroup
): arithm.ModPGroupElement {
    return publicKeys.reduce(
        (jointPubKey, publicKey) => jointPubKey.mul(publicKey), 
        group.getONE()
    );
}

/**
 * Obtain the encrypted sum of an array of ciphertexts
 */
export function sum(
    ciphertexts: arithm.PPGroupElement[],
    ppGroup: arithm.PPGroup
): arithm.PPGroupElement {
    return ciphertexts.reduce(
        (encryptedSum, ciphertext) => encryptedSum.mul(ciphertext),
        ppGroup.getONE()
    );
}

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
        // We have to do this typing mess because of the typing mess of 
        // that is typescript
        (encryptedSum, ciphertext) =>
            (encryptedSum.mul(
                (ciphertext as unknown) as arithm.ModPGroupElement
            ) as unknown) as arithm.PPGroupElement,
        ppGroup.getONE() as arithm.PPGroupElement
    );
}

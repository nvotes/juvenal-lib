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

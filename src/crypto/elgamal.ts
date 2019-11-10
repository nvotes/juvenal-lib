import { arithm } from "../../vendors/vjsc/vjsc-1.1.1"

/**
 * Combines multiple public keys into a single shared public key.
 */
export function create_joint_public_key(
    pub_keys: arithm.ModPGroupElement[],
    group: arithm.ModPGroup
): arithm.ModPGroupElement {
    return pub_keys.reduce(
        (joint_pub_key, pub_key) => joint_pub_key.mul(pub_key), 
        group.getONE()
    );
}

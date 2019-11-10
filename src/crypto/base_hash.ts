import { util } from "../../vendors/vjsc/vjsc-1.1.1";

/**
 * Create base hash.
 * 
 * NOTE: We currently have not implemented this to be compatible with current
 * version of the ElectionGuard SDK, which has not implemented it yet either.
 */
export function create_base_hash(): Uint8Array {
    return util.hexToByteArray("0");
}

/**
 * Create extended base hash.
 * 
 * NOTE: We currently have not implemented this to be compatible with current
 * version of the ElectionGuard SDK, which has not implemented it yet either.
 */
export function create_extended_base_hash(): Uint8Array {
    return util.hexToByteArray("0");
}

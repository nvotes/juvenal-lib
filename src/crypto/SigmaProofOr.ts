import { arithm, crypto, eio } from '../../vendors/vjsc/vjsc-1.1.1'
import { SchnorrProof } from './SchnorrProof'

/**
 * Implements a vjsc SigmaProofOr (CDS) that can be loaded and verified from
 * ElectionGuard code.
 */
export class SigmaProofOr extends crypto.SigmaProofOr {
  constructor(challengeSpace: arithm.PRing, proofs: SchnorrProof[]) {
    super(challengeSpace, proofs)
  }

  instanceToByteTree(instances: arithm.PGroupElement[]): eio.ByteTree {
    return this.sigmaProofs[0].instanceToByteTree(instances[0])
  }
}

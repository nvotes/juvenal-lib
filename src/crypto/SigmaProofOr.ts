import { arithm, crypto, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { SchnorrProof } from './SchnorrProof'


class SigmaProofOr extends crypto.SigmaProofOr {
    constructor(challengeSpace: arithm.PRing, proofs: SchnorrProof[]) {
        super(challengeSpace, proofs)
    }
    
    instanceToByteTree(instances: arithm.PGroupElement[]): eio.ByteTree {
        return this.sigmaProofs[0].instanceToByteTree(instances[0]); 
    }
}
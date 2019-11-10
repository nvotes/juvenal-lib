import { arithm, crypto, eio } from '../../vendors/vjsc/vjsc-1.1.1';

/**
 * Implements a vjsc Schnorr Proof that can be loaded and verified from 
 * ElectionGuard code.
 */
export class SchnorrProof extends crypto.SchnorrProof {
    constructor(homomorphism: arithm.ExpHom) {
        super(homomorphism)
    }

    challenge(first: eio.ByteTree, second: crypto.HashFunction): arithm.PRingElement {
        const digest = second.hash(first.toByteArrayRaw())
        return this.homomorphism.domain.getPField().toElement(digest)
    }

    instanceToByteTree(instance: arithm.PGroupElement): eio.ByteTree {
        return instance.toByteTreeNoZero()
    }

    byteTreeToCommitment(byteTree: eio.ByteTree) {
        return this.homomorphism.range.toElementAlt(byteTree)
    }

    verifyEG(label: Uint8Array, instance: eio.ByteTree, 
        commitment: Uint8Array | eio.ByteTree, 
        challenge: Uint8Array, response: Uint8Array | eio.ByteTree): boolean {
        
        const instanceElement = this.homomorphism.range.toElementAlt(instance)
        
        const cbtt = eio.ByteTree.asByteTree(commitment)
        const rbtt = eio.ByteTree.asByteTree(response)
        
        const proof = new eio.ByteTree([cbtt, rbtt])
        
        const proofb = proof.toByteArray()
        
        return this.verify(label, instanceElement, crypto.sha256, proofb)
    }
}
import { arithm, crypto, eio } from '../../vendors/vjsc/vjsc-1.1.1';

/**
 * Implements a vjsc Schnorr Proof that can be loaded and verified from 
 * ElectionGuard code.
 */
export class SchnorrProof extends crypto.SchnorrProof {
    constructor(homomorphism: arithm.ExpHom) {
        super(homomorphism);
    }

    challenge(first: eio.ByteTree, second: crypto.HashFunction): arithm.PRingElement {
        const digest = second.hash(first.toByteArrayRaw());
        return this.homomorphism.domain.getPField().toElement(digest);
    }

    instanceToByteTree(instance: arithm.PGroupElement): eio.ByteTree {
        return instance.toByteTreeNoZero();
    }

    byteTreeToCommitment(byteTree: eio.ByteTree) {
        return this.homomorphism.range.toElementAlt(byteTree);
    }

    verifyElectionGuard(label: Uint8Array, instance: eio.ByteTree, 
        commitment: Uint8Array | eio.ByteTree, 
        challenge: Uint8Array, 
        response: Uint8Array | eio.ByteTree
    ): boolean {    
        const instanceElement = this.homomorphism.range.toElementAlt(instance);
        
        const commitmentByteTree = eio.ByteTree.asByteTree(commitment);
        const responseByteTree = eio.ByteTree.asByteTree(response);
        
        const proof = new eio.ByteTree([commitmentByteTree, responseByteTree]);
        const proofByteArray = proof.toByteArray();
        
        // TODO: verify that the given challenge equals the calculated one.
        // We currently verify the response, which depends directly on the 
        // challenge, but we should verify all the data we can, and that
        // includes the given challenge.
        return this.verify(
            label, 
            instanceElement, 
            crypto.sha256, 
            proofByteArray
        );
    }
}
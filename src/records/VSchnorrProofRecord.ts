import { VRecord } from './VRecord';
import { VRecorder } from '../recorders/VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { SchnorrProof } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { SchnorrProof as CryptoSchnorrProof } from '../crypto/SchnorrProof';
import { strDecToByteArray, strDecToByteTree } from '../crypto/utils';

/**
 * Verifies a Schnorr Proof record
 */
export class VSchnorrProofRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    /// The record data
    proof: SchnorrProof;

    /// instance = g^witness (mod p), with witness being the secret
    /// that we want to prove we know.
    instance: arithm.ModPGroupElement;

    /// Title of what we are proving, used for text recording purposes
    proofTitle: string;

    /// Hash to use as a label in this proof
    label: Uint8Array;

    constructor(
        parentContext: string[], 
        label: Uint8Array,
        proof: SchnorrProof,
        instance: arithm.ModPGroupElement,
        proofTitle: string
    ) {
        this.context = parentContext.slice();
        this.label = label;
        this.proof = proof;
        this.instance = instance;
        this.proofTitle = proofTitle;
    }

    /// Verify the Schnorr ZKP
    verify(recorder: VRecorder): void {
        const group = this.instance.pGroup;

        // wrapped in a try-catch because deserialization could fail
        try {
            const commitment = strDecToByteArray(this.proof.commitment);
            const challenge = strDecToByteArray(this.proof.challenge);
            const response = strDecToByteArray(this.proof.response);

            const expHom = new arithm.ExpHom(group.pRing, group.getg());
            const schnorrProofVerifier = new CryptoSchnorrProof(expHom);

            const verificationResult = schnorrProofVerifier.verifyElectionGuard(
                this.label, 
                this.instance.toByteTree(), 
                commitment, 
                challenge, 
                response
            );

            recorder.record(
                verificationResult,
                this.context,
                "SchnorrProof",
                "The Schnorr proof of knowledge of " + this.proofTitle +
                " should verify"
            );
        } catch(error) {
            recorder.record(
                false,
                this.context,
                "SchnorrProof",
                "Error during Schnorr proof  of " + this.proofTitle +
                " verification: " + error.message
            );
        }
    }
}
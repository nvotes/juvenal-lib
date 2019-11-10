import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { ChaumPedersenProof } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { SchnorrProof as CryptoSchnorrProof } from '../crypto/SchnorrProof';
import { str_dec_to_byte_array, str_dec_to_byte_tree } from '../crypto/utils';

/**
 * Verifies a Chaum-Pedersen Proof record
 
export class VChaumPedersenProofRecord implements VRecord {
    /// Context of this record
    _context: string[] = [];

    /// The record data
    proof: ChaumPedersenProof;

    /// instance = g^witness (mod p), with witness being the secret
    /// that we want to prove we know.
    instance: arithm.ModPGroupElement;

    /// Title of what we are proving, used for text recording purposes
    proof_title: string;

    /// Hash to use as a label in this proof
    label: Uint8Array;

    constructor(
        parent_context: string[], 
        label: Uint8Array,
        proof: SchnorrProof,
        instance: arithm.ModPGroupElement,
        proof_title: string
    ) {
        this._context = parent_context.slice();
        this.label = label;
        this.proof = proof;
        this.instance = instance;
        this.proof_title = proof_title;
    }

    context(): string[] {
        return this._context;
    }

    /// Verify the Schnorr ZKP
    verify(recorder: VRecorder): void {
        const group = this.instance.pGroup;

        // wrapped in a try-catch because deserialization could fail
        try {
            const commitment = str_dec_to_byte_array(this.proof.commitment);
            const challenge = str_dec_to_byte_array(this.proof.challenge);
            const response = str_dec_to_byte_array(this.proof.response);

            const exp_hom = new arithm.ExpHom(group.pRing, group.getg());
            let schnorr_proof_verifier = new CryptoSchnorrProof(exp_hom);

            const verification_result = schnorr_proof_verifier.verifyEG(
                this.label, 
                this.instance.toByteTree(), 
                commitment, 
                challenge, 
                response
            );

            recorder.record(
                verification_result,
                this.context(),
                "SchnorrProof",
                "The Schnorr proof of knowledge of " + this.proof_title +
                " should verify"
            );
        } catch(e) {
            recorder.record(
                false,
                this.context(),
                "SchnorrProof",
                "Error during Schnorr proof  of " + this.proof_title +
                " verification: " + e.message
            );
        }
    }
}
*/
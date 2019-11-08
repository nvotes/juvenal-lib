import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { SchnorrProof } from 'electionguard-schema-0.85/@types/election_record';
import { arithm, crypto } from '../../vendors/vjsc/vjsc-1.1.1';
import { str_dec_to_byte_array } from '../crypto/utils';

export class VSchnorrProofRecord implements VRecord {
    /// Context of this record
    _context: string[] = [];

    /// The record data
    proof: SchnorrProof;

    /// instance = g^witness (mod p), with witness being the secret
    /// that we want to prove we know.
    instance: arithm.ModPGroupElement;

    /// Title of what we are proving, used for text recording purposes
    proof_title: string;

    constructor(
        parent_context: string[], 
        proof: SchnorrProof,
        instance: arithm.ModPGroupElement,
        proof_title: string
    ) {
        this._context = parent_context.slice();
        this.proof = proof;
        this.instance = instance;
        this.proof_title = proof_title;
    }

    context(): string[] {
        return this._context;
    }

    verify(recorder: VRecorder): void {
        // Verify the Schnorr ZKP
        let group = this.instance.pGroup;
        let hom = new arithm.ExpHom(
            group.pRing, 
            group.getg()
        );

        let extended_base_hash: Uint8Array = new Uint8Array();
        // TODO: Proof should be a combination of:
        // (commitment, reply)
        let proof: Uint8Array = new Uint8Array();

        let verification_result = new crypto.SchnorrProof(hom)
            .verify(
                /*extended_base_hash*/extended_base_hash,
                this.instance.value.toByteArray(),
                crypto.sha256,
                proof
            );
        recorder.record(
            verification_result,
            this.context(),
            "SchnorrProof",
            "The Schnorr proof of knowledge of " + this.proof_title +
            " should verify"
        );
    }
}
import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { VSchnorrProofRecord } from './VSchnorrProofRecord';
import { 
    BigNaturalNumber1, 
    SchnorrProof 
} from 'electionguard-schema-0.85/@types/election_record';
import { arithm } from 'vjsc/vjsc-1.1.1';
import { VCoefficientCommitmentsMatrixRecord } from './VCoefficientCommitmentsMatrixRecord';
import { str_dec_to_modpgroup_element } from '../crypto/utils';

/**
 * Represents a polynomial coefficient commitment in the schema.
 */
export type CoefficcientCommitment = {
    /// The polynomial coefficient
    public_key: BigNaturalNumber1;

    /// Schnorr proof of knowledge of the commitment
    proof: SchnorrProof;
    [k: string]: any;
};

export class VCoefficientCommitmentRecord implements VRecord {
    /// Context of this record
    _context: string[] = [];

    /// Parent record
    parent: VCoefficientCommitmentsMatrixRecord;

    /// The record data
    commitment: CoefficcientCommitment;

    /// The index of this coefficient commitment
    index: number;

    /// Base hash of the election
    base_hash: Uint8Array;

    constructor(
        parent: VCoefficientCommitmentsMatrixRecord,
        commitment: CoefficcientCommitment,
        base_hash: Uint8Array,
        index: number
    ) {
        this._context = parent.context().slice();
        this._context.push("Coefficient #" + index + " commitment");
        this.parent = parent;
        this.commitment = commitment;
        this.base_hash = base_hash;
        this.index = index;
    }

    context(): string[] {
        return this._context;
    }

    verify(recorder: VRecorder): void {
        // Verify the Schnorr ZKP
        let group = this.parent.parent.modp_group();
        let [err, pub_key_el] = str_dec_to_modpgroup_element(
            this.commitment.public_key,
            group
        );
        if (err !== null) {
            recorder.record(
                false,
                this.context(),
                "CoefficientCommitmentVerification",
                "Error loading the coefficient commitment: " + err.message
            );
        }
        new VSchnorrProofRecord(
            this.context(), 
            this.base_hash,
            this.commitment.proof,
            pub_key_el as arithm.ModPGroupElement,
            "Polynomial Coefficient"
        ).verify(recorder);
    }
}
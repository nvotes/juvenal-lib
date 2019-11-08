import { VRecord } from './VRecord';
import { VElectionRecord } from './VElectionRecord';
import { VRecorder } from '../VRecorder';
import { 
    BigNaturalNumber1, 
    SchnorrProof 
} from 'electionguard-schema-0.85/@types/election_record';
import { arithm, util } from '../../vendors/vjsc/vjsc-1.1.1';
import { str_dec_to_modpgroup_element } from '../crypto/utils';
import { 
    CoefficcientCommitment,
    VCoefficientCommitmentRecord
} from './VCoefficientCommitmentRecord';

/**
 * List of polynomial coefficients of a trustee.
 */
export type CoefficientCommitments = [
    CoefficcientCommitment,
    ...CoefficcientCommitment[]
];

/**
 * A list whose elements are the lists of polynomial coefficients of each
 * trustee.
 */
export type CoefficientCommitmentsMatrix = [
    CoefficientCommitments,
    ...CoefficientCommitments[]
];

/**
 * Allows the verification of coefficient commitments matrix records.
 */
export class VCoefficientCommitmentsMatrixRecord implements VRecord {
    /// Reference to the parent election record
    parent: VElectionRecord;

    /// List of polynomial coefficient commitments
    commitments: CoefficientCommitments;

    /// Number of the trustee, starting with 1
    trustee_index: number;

    /// First coefficient of the trustee, which corresponds with the
    /// public key of the trustee.
    first_coefficient_el: arithm.ModPGroupElement;

    /// Context of this record
    _context: string[] = [];

    /**
     * Constructor of the coefficient commitments matrix record.
     * 
     * @param parent Parent election record
     * @param commitments list of polynomial coefficient commitments
     * @param trustee_index Number of the trustee, starting with 1
     */
    constructor(
        parent: VElectionRecord,
        commitments: CoefficientCommitments,
        trustee_index: number
    ) {
        this.parent = parent;
        this.commitments = commitments;
        this.trustee_index = trustee_index;
        this._context = parent.context().slice();
        this._context.push("Trustee #" + trustee_index +" public keys");

        /// Load the first coefficient group element, which is the public key
        let [err, element] = str_dec_to_modpgroup_element(
            commitments[0].public_key,
            this.parent.modp_group()
        );
        if (err !== null) {
            throw err;
        }
        this.first_coefficient_el = element as arithm.ModPGroupElement;
    }

    context(): string[] {
        return this._context;
    }
    
    verify(recorder: VRecorder): void {
        recorder.record(
            // A degree n polynomial is uniquely determined by n + 1 points
            // Therefore necessary threshold = n + 1, so degree = threshold - 1
            // Therefore number of coefficients = threshold (degree n has n + 1
            // coefficients)
            this.commitments.length === this.parent.election.parameters.threshold,
            this.context(),
            "NumberOfCoefficients",
            "The number of coefficients (" +  this.commitments.length +
             ") should be equal to the decryption threhold (" + 
             this.parent.election.parameters.threshold + ")"
        );

        // Verify each of the commitments and their Schnorr ZKP
        this.commitments
            .map((commitment, index) => 
                new VCoefficientCommitmentRecord(
                    this,
                    commitment,
                    index
                )
            )
            .map((v_coefficient) => v_coefficient.verify(recorder));
    }
}
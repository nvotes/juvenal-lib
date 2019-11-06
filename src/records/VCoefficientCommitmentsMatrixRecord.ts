import { VRecord } from './VRecord';
import { VElectionRecord } from './VElectionRecord';
import { VRecorder } from '../VRecorder';
import { 
    BigNaturalNumber1, 
    SchnorrProof 
} from 'electionguard-schema-0.85/@types/election_record';
import { arithm, util } from '../../vendors/vjsc/vjsc-1.1.1';
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
 * The implementation for the coefficient commitments matrix
 */
export class VCoefficientCommitmentsMatrixRecord implements VRecord {
    parent: VElectionRecord;
    coefficients: CoefficientCommitments;
    first_coefficient_el: arithm.ModPGroupElement;

    constructor(parent: VElectionRecord, coefficients: CoefficientCommitments) {
        this.parent = parent;
        this.coefficients = coefficients;
        let [err, element] = str_dec_to_modpgroup_element(
            coefficients[0].public_key,
            this.parent.modp_group()
        );
        if (err !== null) {
            throw err;
        }
        this.first_coefficient_el = element as arithm.ModPGroupElement;
    }
    
    verify(recorder: VRecorder): void {
        // TODO
    }
}
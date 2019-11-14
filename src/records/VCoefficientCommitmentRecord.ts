import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { VSchnorrProofRecord } from './VSchnorrProofRecord';
import { 
    BigNaturalNumber1, 
    SchnorrProof 
} from 'electionguard-schema-0.85/@types/election_record';
import { arithm } from 'vjsc/vjsc-1.1.1';
import { VCoefficientCommitmentsRecord } from './VCoefficientCommitmentsRecord';
import { strDecToModPGroupElement, isError } from '../crypto/utils';

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
    context: string[] = [];

    /// Parent record
    parent: VCoefficientCommitmentsRecord;

    /// The record data
    commitment: CoefficcientCommitment;

    /// The index of this coefficient commitment
    index: number;

    /// Base hash of the election
    baseHash: Uint8Array;

    constructor(
        parent: VCoefficientCommitmentsRecord,
        commitment: CoefficcientCommitment,
        baseHash: Uint8Array,
        index: number
    ) {
        this.context = parent.context.slice();
        this.context.push("Coefficient #" + index + " commitment");
        this.parent = parent;
        this.commitment = commitment;
        this.baseHash = baseHash;
        this.index = index;
    }

    verify(recorder: VRecorder): void {
        // Verify the Schnorr ZKP
        const group = this.parent.parent.modPGroup();
        const publicKeyElement = strDecToModPGroupElement(
            this.commitment.public_key,
            group
        );
        if (isError(publicKeyElement)) {
            const error = publicKeyElement;
            recorder.record(
                false,
                this.context,
                "CoefficientCommitmentLoading",
                "Error loading the coefficient commitment: " + error.message
            );
        } else {
            new VSchnorrProofRecord(
                this.context, 
                this.baseHash,
                this.commitment.proof,
                publicKeyElement,
                "Polynomial Coefficient"
            ).verify(recorder);
        }
    }
}
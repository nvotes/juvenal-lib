import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { EncryptedBallot } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { 
    strDecToByteArray, 
    strDecToByteTree, 
    strDecToModPGroupElement, 
    isError, 
    firstError, 
    strDecToPRingElement
} from '../crypto/utils';
import * as elgamal from '../crypto/elgamal'
import { VChaumPedersenProofRecord } from './VChaumPedersenProofRecord';
import { VZeroOrOneProofRecord } from './VZeroOrOneProofRecord';

export class VContestInfo {
    numSelections: number;
    maxSelections: number;

    constructor(numSelections: number, maxSelections: number) {
        this.numSelections = numSelections;
        this.maxSelections = maxSelections;
    }
}

/**
 * Verifies a encrypted (cast) ballot record.
 */
export class VEncryptedBallotRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    // Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The record data
    encryptedBallot: EncryptedBallot;

    /// Number of selections for each contest
    contestInfoArray: VContestInfo[];

    /// Public key with which this message was encrypted
    publicKey: arithm.ModPGroupElement;

    /**
     * Constructs the verification record object
     * 
     * @param context 
     * @param label
     * @param encryptedBallot 
     * @param contestInfoArray
     * @param publicKey
     * @param index 
     */
    constructor(
        parent_context: string[],
        label: Uint8Array,
        encryptedBallot: EncryptedBallot,
        contestInfoArray: VContestInfo[],
        publicKey: arithm.ModPGroupElement,
        index: number
    ) {
        this.context = parent_context.slice();
        this.context.push("Cast Ballot #" + index);
        this.label = label;
        this.encryptedBallot = encryptedBallot;
        this.contestInfoArray = contestInfoArray;
        this.publicKey = publicKey;
    }

    /// Verify the record
    verify(recorder: VRecorder): void {
        ///////////////// Non-Crypto verifications ///////////////////////////
        /*
        Two verifications not yet done because we cannot do them yet:

        - The date referred in the tracking code of the ballot is posterior to the
          date in the previous ballot. (not yet verifiable)
        - All the ballots for each device are consecutive. (not yet verifiable)
        */
       recorder.record(
            this.encryptedBallot.contests.length == this.contestInfoArray.length,
            this.context,
            "CastBallotNumberOfContests",
            "The number of contests inside the ballot matches the defined " +
            "in the election"
        );

        this.encryptedBallot.contests.map((contest, index) => {
            const contestInfo = this.contestInfoArray[index];
            let context = this.context.slice();
            context.push("Contest #" + index);

            recorder.record(
                (
                    contestInfo !== undefined && 
                    contest.selections.length == contestInfo.numSelections
                ),
                context,
                "CastBallotNumberOfSelections",
                "The number of selections matches the defined for the " +
                "contest"
            );

            recorder.record(
                contest.max_selections == contestInfo.maxSelections,
                context,
                "CastBallotMaxSelections",
                "The maximum number of selections matches the " +
                "defined for the contest"
            );


            ///////////////// Crypto verifications ///////////////////////////////
            /*
            The following verification is not yet doable because ElectionGuard SDK
            does not generate this data correctly:
            The tracking code hash of the ballot is calculated correctly.
            */

            /*
            For each contest:
            - The NIZK Proof that each possible selection is an encryption of zero or one.
            - The Chaum-Pedersen Proof that the sum of the possible selections is equal to
            the number of possible selections of the contest.
            */
           let group = this.publicKey.pGroup;
           const ppGroup = new arithm.PPGroup([group, group]);

           try {
                // Load the encrypted ballot selections for this contest
                // as an arithm.PPGroupElement[] array
                const selections = contest.selections.map(
                    (selection) => {
                        const c1 = strDecToModPGroupElement(
                            selection.message.public_key,
                            group
                        );
                        const c2 = strDecToModPGroupElement(
                            selection.message.ciphertext,
                            group
                        );
                        if (isError(c1) || isError(c2)) {
                            let error = firstError([c1, c2]);
                            throw error;
                        } else {
                            return ppGroup.prod([c1, c2]);
                        }
                    }
                );
                // multiply the selections (ciphertexts) to obtain the encrypted
                // sum of the selections
                const encryptedSum = elgamal.sum(selections, ppGroup);

                const nElement = strDecToPRingElement(
                    contest.max_selections,
                    group.pRing
                );

                if (isError(nElement)) {
                    const error: Error = nElement;
                    throw error;
                } else {
                    // Obtain g^-n
                    const gnInv = group.getg().exp(nElement).inv();

                    // Prove that the number of selections is equal to the number 
                    // of max selections (n). To do that, we homomorphically sum 
                    // the encrypted ballots obtaining an encrypted sum (c1, c2),
                    // and then we verify the Chaum-Pedersen proof (c1, c2/g^n).
                    const chaum_pedersen = new VChaumPedersenProofRecord(
                        context,
                        this.label,
                        /*proof=*/contest.num_selections_proof,
                        /*A=*/encryptedSum.project(0), 
                        /*B=*/encryptedSum.project(1).mul(gnInv), 
                        /*K=*/this.publicKey,
                        "ballot max selections"
                    );
                    chaum_pedersen.verify(recorder);
                }

                // Now we will verify the proofs that each selection is either 
                // of a one or a zero. This is done using Chaum-Pedersen with
                // the Cramer-Damgård-Schoenmakers technique
                selections.map((selection, index) => {
                    const selectionContext = context.slice();
                    selectionContext.push("Selection #" + index);
                    
                    const zeroOrOneProof = new VZeroOrOneProofRecord(
                        selectionContext,
                        this.label,
                        /*zero_proof=*/contest.selections[index].zero_proof,
                        /*one_proof=*/contest.selections[index].one_proof,
                        /*A=*/selection.project(0), 
                        /*B=*/selection.project(1), 
                        /*K=*/this.publicKey,
                        "selection of zero or one"
                    );
                    zeroOrOneProof.verify(recorder);
                });
           } catch(error) {
                recorder.record(
                    false,
                    context,
                    "CastBallot",
                    "Error verifying the encrypted ballot: " + error.message
                );
           }
        });
        

    }
}
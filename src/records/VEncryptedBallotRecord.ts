import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { EncryptedBallot } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { strDecToByteArray, strDecToByteTree } from '../crypto/utils';

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

    /// The record data
    encryptedBallot: EncryptedBallot;

    /// Number of selections for each contest
    contestInfoArray: VContestInfo[];

    /**
     * Constructs the verification record object
     * 
     * @param context 
     * @param encryptedBallot 
     * @param contestInfoArray
     * @param index 
     */
    constructor(
        parent_context: string[],
        encryptedBallot: EncryptedBallot,
        contestInfoArray: VContestInfo[],
        index: number
    ) {
        this.context = parent_context.slice();
        this.context.push("Cast Ballot #" + index);
        this.encryptedBallot = encryptedBallot;
        this.contestInfoArray = contestInfoArray;
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
        });
        

    }
}
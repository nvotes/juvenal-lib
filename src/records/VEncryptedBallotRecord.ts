import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { EncryptedBallot } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { str_dec_to_byte_array, str_dec_to_byte_tree } from '../crypto/utils';

export class VContestInfo {
    num_selections: number;
    max_selections: number;

    constructor(num_selections: number, max_selections: number) {
        this.num_selections = num_selections;
        this.max_selections = max_selections;
    }
}

/**
 * Verifies a encrypted (cast) ballot record.
 */
export class VEncryptedBallotRecord implements VRecord {
    /// Context of this record
    _context: string[] = [];

    /// The record data
    encrypted_ballot: EncryptedBallot;

    /// Number of selections for each contest
    contest_info_array: VContestInfo[];

    /**
     * Constructs the verification record object
     * 
     * @param context 
     * @param encrypted_ballot 
     * @param contest_info_array
     * @param index 
     */
    constructor(
        parent_context: string[],
        encrypted_ballot: EncryptedBallot,
        contest_info_array: VContestInfo[],
        index: number
    ) {
        this._context = parent_context.slice();
        this._context.push("Cast Ballot #" + index);
        this.encrypted_ballot = encrypted_ballot;
        this.contest_info_array = contest_info_array;
    }

    context(): string[] {
        return this._context;
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
            this.encrypted_ballot.contests.length == this.contest_info_array.length,
            this.context(),
            "CastBallotNumberOfContests",
            "The number of contests inside the ballot matches the defined " +
            "in the election"
        );

        this.encrypted_ballot.contests.map((contest, index) => {
            const contest_info = this.contest_info_array[index];
            let context = this._context.slice();
            context.push("Contest #" + index);

            recorder.record(
                (
                    contest_info !== undefined && 
                    contest.selections.length == contest_info.num_selections
                ),
                context,
                "CastBallotNumberOfSelections",
                "The number of selections matches the defined for the " +
                "contest"
            );

            recorder.record(
                contest.max_selections == contest_info.max_selections,
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
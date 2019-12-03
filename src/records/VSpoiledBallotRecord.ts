import { VRecord } from './VRecord';
import { VRecorder } from '../recorders/VRecorder';
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1';
import { DecryptionShare, ElGamalMessage2 } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { VDecryptionRecord } from './VDecryptionRecord';
import { flatten2D } from '../crypto/utils'
import { VContestInfo } from './VEncryptedBallotRecord'

export type SpoiledDecryption = {
    encrypted_message: ElGamalMessage2;
    decrypted_message: string | number;
    /**
     * The decryption shares `M_i` used to compute the decryption `M`.
     */
    shares: DecryptionShare[]
    /**
     * The actual value encrypted, so either a zero or a one.
     */
    cleartext: number
}

type SpoiledDecryptions = SpoiledDecryption[]

export class VSpoiledBallotRecord implements VRecord {
    /// Context of this record
    context: string[] = []

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array

    /// The lists of spoiled decryptions, one list per contest
    contestDecryptions: SpoiledDecryptions[]

    /// Number of selections for each contest
    contestInfoArray: VContestInfo[]

    /// Public keys for trustees
    publicKeys: arithm.ModPGroupElement[]

    /// The contest number in the election
    index: number

    constructor(
        parent_context: string[],
        label: Uint8Array,
        contestDecryptions: SpoiledDecryptions[],
        contestInfoArray: VContestInfo[],
        publicKeys: arithm.ModPGroupElement[],
        index: number
    ) {
        this.context = parent_context.slice()
        this.context.push("Spoiled ballot #" + index)
        this.label = label
        this.contestDecryptions = contestDecryptions
        this.contestInfoArray = contestInfoArray
        this.publicKeys = publicKeys
        this.index = index
    }

    verify(recorder: VRecorder): void {
        const decryptions = this.contestDecryptions.map(
            (contestDecryption, contestIndex) => {
                const context = this.context.slice()
                context.push("Contest #" + contestIndex)

                // Verify that the sum of the plaintexts of each contest is 
                // equal to the sum of possible selections of the contest
                let cleartextSum = contestDecryption.reduce(
                    (total, next) => total + next.cleartext,
                    0
                )
                let contestInfo = this.contestInfoArray[contestIndex]

                recorder.record(
                    contestInfo !== undefined && cleartextSum == contestInfo.maxSelections,
                    context,
                    "SumOfPlaintexts",
                    "The sum of the plaintexts matches the sum of possible " + 
                    "selections of the contest"
                )

                return contestDecryption.map(
                    (decryption, selectionIndex) =>
                    new VDecryptionRecord(
                        context,
                        this.label,
                        decryption,
                        /*selectionEncryptions=not needed for spoiled ballots*/[],
                        this.publicKeys,
                        selectionIndex
                    )
                )
            }
        )
        
        const flat = flatten2D(decryptions)
        flat.map((decryption) => decryption.verify(recorder))    
    }
}
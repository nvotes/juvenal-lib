import { VRecord } from './VRecord'
import { VRecorder } from '../VRecorder'
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1'
import { 
    TallyDecryption, EncryptedBallot 
} 
from '../../vendors/electionguard-schema-0.85/@types/election_record'
import { VDecryptionRecord } from './VDecryptionRecord'
import { ElGamalMessage } from '../../vendors/electionguard-schema-0.85/@types/decryption_share';


export type ContestTallyDecryptions = [
    TallyDecryption,
    ...TallyDecryption[]
];

export class VContestTallyRecord implements VRecord {
    /// Context of this record
    context: string[] = []

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The list of all tally decryption objects
    tallyDecryptions: ContestTallyDecryptions
    
    /// The list of ballots, used to verify that the encrypted sum of them 
    /// equals to the encrypted tally
    cast_ballots: EncryptedBallot[]

    /// Public keys for trustees
    publicKeys: arithm.ModPGroupElement[]

    /// The contest number in the election
    index: number

    constructor(
        parent_context: string[],
        label: Uint8Array,
        tallyDecryptions: ContestTallyDecryptions,
        cast_ballots: EncryptedBallot[],
        publicKeys: arithm.ModPGroupElement[],
        index: number
    ) {
        this.context = parent_context.slice()
        this.context.push("Tally, contest #" + index)
        this.label = label
        this.tallyDecryptions = tallyDecryptions
        this.cast_ballots = cast_ballots
        this.publicKeys = publicKeys
        this.index = index
    }

    getSelectionEncryptions(selectionIndex: number): ElGamalMessage[] {
        return this.cast_ballots
            .map((ballot) => 
                ballot.contests[this.index].selections[selectionIndex].message
            )
    }

    verify(recorder: VRecorder): void {
        const decryptions = this.tallyDecryptions.map(
            (tallyDecryption, selectionIndex) =>
            
            new VDecryptionRecord(
                this.context,
                this.label,
                tallyDecryption,
                this.getSelectionEncryptions(selectionIndex),
                this.publicKeys,
                selectionIndex
            ) 
        )

        decryptions.map((decryption) => decryption.verify(recorder))
    }
}


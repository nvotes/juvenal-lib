import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1';
import { 
    TallyDecryption 
} 
from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { VDecryptionRecord } from './VDecryptionRecord'


export type ContestTallyDecryptions = [
    TallyDecryption,
    ...TallyDecryption[]
];

export class VContestTallyRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The list of all tally decryption objects
    tallyDecryptions: ContestTallyDecryptions

    /// Public keys for trustees
    publicKeys: arithm.ModPGroupElement[]

    /// The contest number in the election
    index: number

    constructor(
        parent_context: string[],
        label: Uint8Array,
        tallyDecryptions: ContestTallyDecryptions,
        publicKeys: arithm.ModPGroupElement[],
        index: number
    ) {
        this.context = parent_context.slice();
        this.context.push("Tally, contest #" + index);
        this.label = label
        this.tallyDecryptions = tallyDecryptions
        this.publicKeys = publicKeys
        this.index = index
    }

    verify(recorder: VRecorder): void {
        const decryptions = this.tallyDecryptions.map(
            (tallyDecryption, index) =>
            
            new VDecryptionRecord(
                this.context,
                this.label,
                tallyDecryption,
                this.publicKeys,
                index
            ) 
        )

        decryptions.map((decryption) => decryption.verify(recorder))
    }
}


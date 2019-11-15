import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1';
import { DecryptionShare, ElGamalMessage2 } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { VDecryptionRecord } from './VDecryptionRecord';
import { flatten2D } from '../crypto/utils'

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
    context: string[] = [];

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The lists of spoiled decryptions, one list per contest
    contestDecryptions: SpoiledDecryptions[]

    /// Public keys for trustees
    publicKeys: arithm.ModPGroupElement[]

    /// The contest number in the election
    index: number

    constructor(
        parent_context: string[],
        label: Uint8Array,
        contestDecryptions: SpoiledDecryptions[],
        publicKeys: arithm.ModPGroupElement[],
        index: number
    ) {
        this.context = parent_context.slice();
        this.context.push("Spoiled ballot #" + index);
        this.label = label
        this.contestDecryptions = contestDecryptions
        this.publicKeys = publicKeys
        this.index = index
    }

    verify(recorder: VRecorder): void {
        const decryptions = this.contestDecryptions.map(
            (contestDecryption, index) => {
                const context = this.context.slice()
                context.push("Contest #" + index)

                return contestDecryption.map(
                    (decryption, index) =>
                    new VDecryptionRecord(
                        context,
                        this.label,
                        decryption,
                        this.publicKeys,
                        index
                    )
                )
            }
        )
        
        const flat = flatten2D(decryptions)
        flat.map((decryption) => decryption.verify(recorder))    
    }
}
import { VRecord } from './VRecord';
import { VRecorder } from '../VRecorder';
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1';

import { VChaumPedersenProofRecord } from './VChaumPedersenProofRecord';
import { ElGamalMessage } from 'electionguard-schema-0.85/@types/ballot_decryption';
import { SpoiledDecryption } from './VSpoiledBallotRecord'

import { 
    TallyDecryption, 
    DecryptionShare,
    BigNaturalNumber8 } 
from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { 
    strDecToModPGroupElement,
    strDecToPRingElement,
    isError,
    firstError
}
from '../crypto/utils';

export class VDecryptionRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The object containing all decryption information
    decryption: TallyDecryption | SpoiledDecryption
    
    /// Public keys for trustees
    publicKeys: arithm.ModPGroupElement[]
    
    /// The selection number in the contest
    index: number
    
    /**
     * Constructs the verification record object
     * 
     * @param context 
     * @param label
     * @param decryption
     * @param publicKeys
     * @param index 
     */
    constructor(
        parent_context: string[],
        label: Uint8Array,
        decryption: TallyDecryption | SpoiledDecryption,
        publicKeys: arithm.ModPGroupElement[],
        index: number
    ) {
        this.context = parent_context.slice()
        this.context.push("Selection #" + index)
        this.label = label
        this.decryption = decryption
        this.publicKeys = publicKeys
        this.index = index
    }

    /// Verify tally decryption
    /// 1. Shares were computed correctly
    /// 2. Decryption was correctly computed from shares
    /// 3. Cleartext corresponds to decryption
    verify(recorder: VRecorder): void {
        const group = this.publicKeys[0].pGroup
        /* const encrypted = this.decryptedTally.encrypted_tally
        const decrypted = this.decryptedTally.decrypted_tally
        const shares = this.decryptedTally.shares
        const cleartext = this.decryptedTally.cleartext*/
        const [encrypted, decrypted, shares, cleartext] = 
            this.extractDecryptionValues()

        const alpha = strDecToModPGroupElement(
            encrypted.public_key,
            group
        )
        const beta = strDecToModPGroupElement(
            encrypted.ciphertext,
            group
        )
        const gMessage = strDecToModPGroupElement(
            decrypted,
            group
        )
        
        if (isError(alpha)) {
            const error: Error = alpha;
            recorder.record(
                false,
                this.context,
                "AlphaLoading",
                "Error converting alpha from encrypted_tally: " + error.message
            )
        } else {
            const shareRecords = shares.map(
                (decryptionShare, index) =>
                new VDecryptionShareRecord(
                    this.context, 
                    this.label,
                    decryptionShare,
                    this.publicKeys[index],
                    alpha,
                    index
                )
            )
            const result = shareRecords.map((share) => share.verify(recorder))
            if(this.allShares(result)) {
                const shareElements: arithm.ModPGroupElement[] = result
                const combined = shareElements.reduce(
                    (value, next) => value.mul(next)
                )
            
                if(!isError(beta) && !isError(gMessage)) {    
                    const lhs = beta.mul(combined.inv())
                    // verify that encrypted * (1/sum(shares)) = decrypted
                    recorder.record(
                        lhs.equals(gMessage),
                        this.context,
                        "DecryptionMatches",
                        "Decryption computed with shares should match"
                    )
                    const clearElement = strDecToPRingElement(
                        cleartext, group.pRing
                    )
                    if(!isError(clearElement)) {
                        // verify that g^cleartext = gMessage
                        recorder.record(
                            group.getg().exp(clearElement).equals(gMessage),
                            this.context,
                            "CleartextMatches",
                            "Cleartext exponentiation should match decrypted"
                        )
                    }
                    
                }
                else {
                    const error: Error = firstError([
                        beta,
                        gMessage,
                    ]);
                    recorder.record(
                        false,
                        this.context,
                        "DecryptionData",
                        "Error loading beta and decrypted tally " +
                        ": " + error.message
                    );
                }
            }
            else {
                recorder.record(
                    false,
                    this.context,
                    "SharesLoading",
                    "Not all shares were loaded correctly"
                )
            }
        }
    }

    extractDecryptionValues(): [
        ElGamalMessage, 
        BigNaturalNumber8, 
        DecryptionShare[], 
        number] 
        {
        
        if(this.isTallyDecryption(this.decryption)) {
            return [
                this.decryption.encrypted_tally,
                this.decryption.decrypted_tally,
                this.decryption.shares,
                this.decryption.cleartext
            ]
        }
        else {
            return [
                this.decryption.encrypted_message,
                this.decryption.decrypted_message,
                this.decryption.shares,
                this.decryption.cleartext
                ]
        }
    }

    private isTallyDecryption(value: TallyDecryption | SpoiledDecryption)
        : value is TallyDecryption {
            
        return (value as TallyDecryption).decrypted_tally !== undefined
    } 
    
    /// type guard to convert array of (modp | errors)[] to modp[]
    private allShares(
        obj: (arithm.ModPGroupElement | Error)[] | 
        arithm.ModPGroupElement[]
        ): obj is arithm.ModPGroupElement[] {
        
        return obj.filter((value) => !isError(value))
            .length == obj.length
    }
}

class VDecryptionShareRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The share (partial decryption + proof) computed by a trustee
    share: DecryptionShare

    /// The public key corresponding to the trustee that 
    // computed the share (partial decryption)
    publicKey: arithm.ModPGroupElement

    // The alpha element of the ciphertext with which the 
    // share was computed
    alpha: arithm.ModPGroupElement

    // The share number (and trustee number)
    index: number

    /**
     * Constructs the verification record object
     * 
     * @param parent_context 
     * @param label
     * @param share
     * @param publicKey
     * @param alpha
     * @param index
     */
    constructor(
        parent_context: string[],
        label: Uint8Array,
        share: DecryptionShare,
        publicKey: arithm.ModPGroupElement,
        alpha: arithm.ModPGroupElement,
        index: number
    ) {
        this.context = parent_context.slice()
        this.context.push("Share #" + index)
        this.label = label
        this.share = share
        this.publicKey = publicKey
        this.alpha = alpha
        this.index = index + 1
    }

    /// Verify the proof of partial decryption (Chaum-Pedersen)
    verify(recorder: VRecorder): arithm.ModPGroupElement | Error {
        const shareElement = strDecToModPGroupElement(
            this.share.share,
            this.publicKey.pGroup
        )
        if(isError(shareElement)) {
            const error: Error = shareElement;
            recorder.record(
                false,
                this.context,
                "ShareLoading",
                "Error converting share: " + error.message
            )
        } else {
            const chaum_pedersen = new VChaumPedersenProofRecord(
                this.context,
                this.label,
                this.share.proof,
                this.publicKey, 
                shareElement, 
                this.alpha,
                "share correctness"
            );
            chaum_pedersen.verify(recorder)
        }

        return shareElement
    }
}
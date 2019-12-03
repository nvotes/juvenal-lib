import { VRecord } from './VRecord';
import { VRecorder } from '../recorders/VRecorder';
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1';
import { VChaumPedersenProofRecord } from './VChaumPedersenProofRecord';
import { ElGamalMessage } from 'electionguard-schema-0.85/@types/ballot_decryption';
import { SpoiledDecryption } from './VSpoiledBallotRecord'
import { EncryptedBallot } from '../../vendors/electionguard-schema-0.85/@types/encrypted_ballot';
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
import * as elgamal from '../crypto/elgamal'


export class VDecryptionRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    /// Label using during hashing for non-interactive protocols
    label: Uint8Array;

    /// The object containing all decryption information
    decryption: TallyDecryption | SpoiledDecryption

    /// List of selection encryptions from each cast ballot
    /// corresponding to this decryption. 
    ///
    /// Note that this is only used if it's a tally decryption.
    selectionEncryptions: ElGamalMessage[]
    
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
     * @param selectionEncryptions
     * @param publicKeys
     * @param selectionIndex 
     */
    constructor(
        parent_context: string[],
        label: Uint8Array,
        decryption: TallyDecryption | SpoiledDecryption,
        selectionEncryptions: ElGamalMessage[],
        publicKeys: arithm.ModPGroupElement[],
        selectionIndex: number
    ) {
        this.context = parent_context.slice()
        this.context.push("Selection #" + selectionIndex)
        this.label = label
        this.decryption = decryption
        this.selectionEncryptions = selectionEncryptions
        this.publicKeys = publicKeys
        this.index = selectionIndex
    }

    /// Verify tally decryption or spoiled ballot
    /// 1. (if tally decryption) The encrypted tally is the sum of encrypted cast ballots
    /// 2. Shares were computed correctly
    /// 3. Decryption was correctly computed from shares
    /// 4. Cleartext corresponds to decryption
    verify(recorder: VRecorder): void {
        const group = this.publicKeys[0].pGroup
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
                    if(this.isTallyDecryption(this.decryption)) {
                        // Verify that the encrypted tally is the sum of encrypted cast ballots
                        const ppGroup = new arithm.PPGroup([group, group])
                        try {
                            // Load the encrypted ballot selections for this contest
                            // as an arithm.PPGroupElement[] array
                            const selections = this.selectionEncryptions.map(
                                (selection) => {
                                    
                                    const selectionAlpha = strDecToModPGroupElement(
                                        selection.public_key,
                                        group
                                    )
                                    const selectionBeta = strDecToModPGroupElement(
                                        selection.ciphertext,
                                        group
                                    )
                                    if (isError(selectionAlpha) || isError(selectionBeta)) {
                                        let error = firstError([selectionAlpha, selectionBeta])
                                        throw error
                                    } else {
                                        return ppGroup.prod([selectionAlpha, selectionBeta])
                                    }
                                }
                            )
                            // multiply the selections (ciphertexts) to obtain the encrypted
                            // sum of the selections
                            const calculatedEncryptedSum = elgamal.sum(selections, ppGroup)
                            const givenEncryptedTally = ppGroup.prod([alpha, beta])
                            recorder.record(
                                calculatedEncryptedSum.equals(givenEncryptedTally),
                                this.context,
                                "TallySum",
                                "The encrypted tally should match the sum of encrypted cast ballots"
                            )
                        } catch(error) {
                            recorder.record(
                                false,
                                this.context,
                                "LoadingBallots",
                                "Not all ballots were loaded correctly: " + error.message
                            )
                        }
                    }
                    
                    // execute the decryption
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
        number
    ] {
        
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
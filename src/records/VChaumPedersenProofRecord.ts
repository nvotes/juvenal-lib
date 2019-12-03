import { VRecord } from './VRecord';
import { VRecorder } from '../recorders/VRecorder';
import { arithm, crypto, util, eio } from '../../vendors/vjsc/vjsc-1.1.1';
import { ChaumPedersenProof } from '../../vendors/electionguard-schema-0.85/@types/election_record';
import { SchnorrProof as CryptoSchnorrProof } from '../crypto/SchnorrProof';
import { 
    strDecToByteArray, 
    strDecToByteTree, 
    isError,
    firstError
} from '../crypto/utils';

/**
 * Verifies a Chaum-Pedersen Proof record.
 * 
 * A Chaum-Pedersen proof of knowledge proves the equivalence of discrete 
 * logarithms without revealing the value of the discrete logarithm itself.
 * 
 * This means we will verify that given two numbers A, and B, both numbers
 * follow the two following formulas and we know but don't reveal the 
 * number 'witness': 
 * 
 * A = g^witness (mod p)
 * B = K^witness (mod p)
 * 
 * This can be used to prove that an encrypted exponential ElGamal message,
 * that is of the form (c1, c2) = (g^r, g^m * K^r) is of a specific value
 * 'm' (for example 0, 1, or 56) if we use a Chaum-Pedersen proof with
 * values (A, B) = (c1, c2 / g^m) = (g^r, K^r).
 * 
 * In the code, we verify the Chaum-Pedersen proof using as generalized 
 * SigmaProof using the SchnorrProof class from the verificatum library 
 * vjsc.
 */
export class VChaumPedersenProofRecord implements VRecord {
    /// Context of this record
    context: string[] = [];

    /// The record data
    proof: ChaumPedersenProof;

    /// A = g^witness (mod p)
    A: arithm.ModPGroupElement;

    /// B = K^witness (mod p)
    B: arithm.ModPGroupElement;

    /// The second base used in for B, usually the public key of an encrypted
    /// message, but could be any number of Gq
    K: arithm.ModPGroupElement;

    /// Title of what we are proving, used for text recording purposes
    proofTitle: string;

    /// Hash to use as a label in this proof
    label: Uint8Array;

    constructor(
        parentContext: string[], 
        label: Uint8Array,
        proof: ChaumPedersenProof,
        A: arithm.ModPGroupElement,
        B: arithm.ModPGroupElement,
        K: arithm.ModPGroupElement,
        proofTitle: string
    ) {
        this.context = parentContext.slice();
        this.label = label;
        this.proof = proof;
        this.A = A;
        this.B = B;
        this.K = K;
        this.proofTitle = proofTitle;
    }

    /// Verify the ZKP
    verify(recorder: VRecorder): void {
        const group = this.K.pGroup;

        // wrapped in a try-catch because deserialization could fail
        try {
            const challenge = strDecToByteArray(this.proof.challenge);
            const response = strDecToByteArray(this.proof.response);
            
            const ppGroup = new arithm.PPGroup([group, group]);
            const pair = ppGroup.prod([group.getg(), this.K]);
            
            const expHomProd = new arithm.ExpHom(group.pRing, pair);
            const schnorrProofVerifier = new CryptoSchnorrProof(expHomProd);

            const AbyteTree = this.A.toByteTree();
            const BbyteTree = this.B.toByteTree();
            
            const commitment1 = strDecToByteTree(
                this.proof.commitment.public_key,
                group.modulusByteLength
            );
            const commitment2 = strDecToByteTree(
                this.proof.commitment.ciphertext,
                group.modulusByteLength
            );

            if (!isError(commitment1)  && !isError(commitment2)) {
                const instancePair = new eio.ByteTree([
                    AbyteTree, 
                    BbyteTree
                ]);
                const commitmentPair = new eio.ByteTree([
                    commitment1, 
                    commitment2
                ]);
                const verificationResult = schnorrProofVerifier
                    .verifyElectionGuard(
                        this.label, 
                        instancePair, 
                        commitmentPair, 
                        challenge, 
                        response
                    );
                recorder.record(
                    verificationResult,
                    this.context,
                    "ChaumPedersenProof",
                    "The Chaum-Pedersen proof of " + this.proofTitle +
                    " should verify"
                );
            } else {
                const error: Error = firstError([
                    commitment1,
                    commitment2    
                ]);
                recorder.record(
                    false,
                    this.context,
                    "ChaumPedersenProof",
                    "Error loading the Chaum-Pedersen proof of " 
                    + this.proofTitle + ": " + error.message
                );
            }
        } catch(error) {
            recorder.record(
                false,
                this.context,
                "ChaumPedersenProof",
                "Error during the verification of the Chaum-Pedersen proof " +
                "of " + this.proofTitle + ": " + error.message
            );
        }
    }
}
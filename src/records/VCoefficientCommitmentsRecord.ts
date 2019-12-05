import { VRecord } from './VRecord'
import { VElectionRecord } from './VElectionRecord'
import { VRecorder } from '../recorders/VRecorder'
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1'
import { strDecToModPGroupElement, isError } from '../crypto/utils'
import {
  CoefficientCommitment,
  VCoefficientCommitmentRecord
} from './VCoefficientCommitmentRecord'

/**
 * List of polynomial coefficients of a trustee.
 */
export type CoefficientCommitments = [
  CoefficientCommitment,
  ...CoefficientCommitment[]
]

/**
 * Allows the verification of coefficient commitments matrix records.
 */
export class VCoefficientCommitmentsRecord implements VRecord {
  /// Reference to the parent election record
  parent: VElectionRecord

  /// List of polynomial coefficient commitments
  commitments: CoefficientCommitments

  /// Number of the trustee, starting with 1
  trusteeIndex: number

  /// First coefficient of the trustee, which corresponds with the
  /// public key of the trustee
  firstCoefficientElement: arithm.ModPGroupElement

  /// Context of this record
  context: string[] = []

  /// Base hash of the election
  baseHash: Uint8Array

  /**
   * Constructor of the coefficient commitments record for a trustee.
   *
   * @param parent Parent election record
   * @param commitments list of polynomial coefficient commitments
   * @param trusteeIndex Number of the trustee, starting with 1
   */
  constructor(
    parent: VElectionRecord,
    commitments: CoefficientCommitments,
    baseHash: Uint8Array,
    trusteeIndex: number
  ) {
    this.parent = parent
    this.commitments = commitments
    this.baseHash = baseHash
    this.trusteeIndex = trusteeIndex
    this.context = parent.context.slice()
    this.context.push('Trustee #' + trusteeIndex + ' public keys')

    /// Load the first coefficient group element, which is the public key
    const element = strDecToModPGroupElement(
      commitments[0].public_key,
      this.parent.modPGroup()
    )
    if (isError(element)) {
      const error: Error = element
      throw error
    }
    this.firstCoefficientElement = element
  }

  verify(recorder: VRecorder): void {
    recorder.record(
      // A degree n polynomial is uniquely determined by n + 1 points
      // Therefore necessary threshold = n + 1, so degree = threshold - 1
      // Therefore number of coefficients = threshold (degree n has n + 1
      // coefficients)
      this.commitments.length === this.parent.election.parameters.threshold,
      this.context,
      'NumberOfCoefficients',
      'The number of coefficients (' +
        this.commitments.length +
        ') should be equal to the decryption threhold (' +
        this.parent.election.parameters.threshold +
        ')'
    )

    // Verify each of the commitments and their Schnorr ZKP
    this.commitments
      .map(
        (commitment, index) =>
          new VCoefficientCommitmentRecord(
            this,
            commitment,
            this.baseHash,
            index
          )
      )
      .map(vCoefficient => vCoefficient.verify(recorder))
  }
}

import { VRecord } from './VRecord'
import { VRecorder } from '../recorders/VRecorder'
import { arithm } from '../../vendors/vjsc/vjsc-1.1.1'
import {
  TallyDecryption,
  EncryptedBallot
} from '../../vendors/electionguard-schema-0.85/@types/election_record'
import { VDecryptionRecord } from './VDecryptionRecord'
import { ElGamalMessage } from '../../vendors/electionguard-schema-0.85/@types/decryption_share'
import { VContestInfo } from './VEncryptedBallotRecord'

export type ContestTallyDecryptions = [TallyDecryption, ...TallyDecryption[]]

export class VContestTallyRecord implements VRecord {
  /// Context of this record
  context: string[] = []

  /// Label using during hashing for non-interactive protocols
  label: Uint8Array

  /// The list of all tally decryption objects
  tallyDecryptions: ContestTallyDecryptions

  /// The list of ballots, used to verify that the encrypted sum of them
  /// equals to the encrypted tally
  castBallots: EncryptedBallot[]

  /// Number of selections for each contest
  contestInfoArray: VContestInfo[]

  /// Public keys for trustees
  publicKeys: arithm.ModPGroupElement[]

  /// The contest number in the election
  contestIndex: number

  constructor(
    parentContext: string[],
    label: Uint8Array,
    tallyDecryptions: ContestTallyDecryptions,
    castBallots: EncryptedBallot[],
    contestInfoArray: VContestInfo[],
    publicKeys: arithm.ModPGroupElement[],
    contestIndex: number
  ) {
    this.context = parentContext.slice()
    this.context.push('Tally, contest #' + contestIndex)
    this.label = label
    this.tallyDecryptions = tallyDecryptions
    this.castBallots = castBallots
    this.contestInfoArray = contestInfoArray
    this.publicKeys = publicKeys
    this.contestIndex = contestIndex
  }

  getSelectionEncryptions(
    selectionIndex: number,
    recorder: VRecorder
  ): ElGamalMessage[] {
    try {
      return this.castBallots.map(
        ballot =>
          ballot.contests[this.contestIndex].selections[selectionIndex].message
      )
    } catch (e) {
      recorder.record(
        false,
        this.context,
        'SelectionEncryptionsLoading',
        'Error loading the selection encryptions: ' + e.message
      )
      return []
    }
  }

  verify(recorder: VRecorder): void {
    const decryptions = this.tallyDecryptions.map(
      (tallyDecryption, selectionIndex) =>
        new VDecryptionRecord(
          this.context,
          this.label,
          tallyDecryption,
          this.getSelectionEncryptions(selectionIndex, recorder),
          this.publicKeys,
          selectionIndex
        )
    )

    decryptions.map(decryption => decryption.verify(recorder))
  }
}

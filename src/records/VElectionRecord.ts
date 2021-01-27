import Ajv, { ErrorObject, ValidateFunction } from 'ajv'
import { arithm, util } from '../../vendors/vjsc/vjsc-1.1.1'
import { ElectionRecord } from '../../vendors/electionguard-schema-0.85/@types/election_record'
import { schemas } from '../../vendors/electionguard-schema-0.85/json_schemas'

import { VRecord } from './VRecord'
import { VRecorder } from '../recorders/VRecorder'
import { strDecToHex, strDecToModPGroupElement, isError } from '../crypto/utils'
import { baselineParameters as modPGroup } from '../crypto/baselineParams'
import { VCoefficientCommitmentsRecord } from './VCoefficientCommitmentsRecord'
import { createJointPublicKey } from '../crypto/elgamal'
import { createBaseHash, createExtendedBaseHash } from '../crypto/baseHash'
import { VEncryptedBallotRecord, VContestInfo } from './VEncryptedBallotRecord'
import { VContestTallyRecord } from './VContestTallyRecord'
import { VSpoiledBallotRecord } from './VSpoiledBallotRecord'

/**
 * Using the election schemas, returns a correctly initialized Ajv schema
 * validator.
 */
function getElectionSchemaValidator(): ValidateFunction {
  const ajv = new Ajv({ allErrors: true })

  // add related schemas to the validator
  for (const [key, value] of Object.entries(schemas)) {
    ajv.addSchema(value, key)
  }

  const validate = ajv.compile(schemas['election_record.schema.json'])
  return validate
}

/**
 * Election record implementation
 */
export class VElectionRecord implements VRecord {
  election: ElectionRecord
  context: string[] = ['Election']

  constructor(electionRecord: ElectionRecord) {
    this.election = electionRecord
  }

  /**
   * Returns the baseline parameters. Currently, this is hardcoded as
   * it is in ElectionGuard SDK.
   */
  modPGroup(): arithm.ModPGroup {
    return modPGroup
  }

  verify(recorder: VRecorder): void {
    ///////////////// Non-Crypto verifications ///////////////////////////

    // validate the JSON schema
    const validate = getElectionSchemaValidator()
    const valid = validate(this.election)
    if (!valid) {
      ;(validate.errors as ErrorObject[]).forEach((error) =>
        recorder.record(
          /*status=*/ false,
          this.context,
          'ValidateJsonSchema',
          error.dataPath + ' ' + error.message
        )
      )
    } else {
      // record successful verification
      recorder.record(
        /*status=*/ true,
        this.context,
        'ValidateJsonSchema',
        'Election record JSON schema should validate'
      )
    }

    // Verify some invariants related to the election that the json schema
    // cannot verify itself
    recorder.record(
      this.election.parameters.threshold <=
        this.election.parameters.num_trustees,
      this.context,
      'ThresholdTrustees',
      'The threshold of trustees that can decrypt the election should ' +
        'be less than or equal to the number of trustees'
    )
    recorder.record(
      this.election.trustee_public_keys.length ==
        this.election.parameters.num_trustees,
      this.context,
      'NumPubKeys',
      'The number of trustee public keys is equal to the defined ' +
        'number of trustees'
    )
    // TODO: we should verify that the election.parameters.date is not
    // in the future, as it has been already tallied. This can't be done
    // currently because dates are not being correctly specified in the
    // schema.

    ///////////////// Crypto verifications ///////////////////////////////

    recorder.record(
      new arithm.LargeInteger(
        strDecToHex(this.election.parameters.prime)
      ).equals(modPGroup.modulus),
      this.context,
      'BaselineEncryptionModulus',
      'The election should use baseline encryption modulus'
    )

    recorder.record(
      new arithm.LargeInteger(
        strDecToHex(this.election.parameters.generator)
      ).equals(modPGroup.getg().value),
      this.context,
      'BaselineEncryptionGenerator',
      'The election should use baseline encryption group generator'
    )

    const baseHash = util.hexToByteArray(this.election.base_hash)
    const extendedBaseHash = util.hexToByteArray(
      this.election.extended_base_hash
    )

    recorder.record(
      util.equalsArray(baseHash, createBaseHash()),
      this.context,
      'ElectionBaseHash',
      'The election base hash should be correctly computed'
    )

    recorder.record(
      util.equalsArray(extendedBaseHash, createExtendedBaseHash()),
      this.context,
      'ElectionExtendedBaseHash',
      'The election extended base hash should be correctly computed'
    )

    // Initialize verification public key records
    let vCoefficients: VCoefficientCommitmentsRecord[] = []
    try {
      vCoefficients = this.election.trustee_public_keys.map(
        (publicKeyRecord, index) =>
          new VCoefficientCommitmentsRecord(
            this,
            publicKeyRecord,
            baseHash,
            index + 1
          )
      )
    } catch (error) {
      recorder.record(
        false,
        this.context,
        'CoefficientCommitmentsLoading',
        'Error loading trustees coefficient ' + 'commitments: ' + error.message
      )
    }

    // Verify that the public key of the election should be the combination
    // of the public keys of all the trustees
    const calculatedJointPublicKey = createJointPublicKey(
      vCoefficients.map((publicKey) => publicKey.firstCoefficientElement),
      modPGroup
    )

    const jointPublicKey = strDecToModPGroupElement(
      this.election.joint_public_key,
      modPGroup
    )

    if (isError(jointPublicKey)) {
      const error: Error = jointPublicKey
      recorder.record(
        false,
        this.context,
        'JointPublicKeyCalculation',
        'Error loading the public key of the election: ' + error.message
      )
    } else {
      recorder.record(
        calculatedJointPublicKey.equals(jointPublicKey),
        this.context,
        'JointPublicKeyCalculation',
        'The public key of the election should be the combination ' +
          'of the public keys of all the trustees'
      )
    }

    // Verify coefficient records
    vCoefficients.map((vCoefficient) => vCoefficient.verify(recorder))

    // TODO: get contest selections from ballot coding file. Currently
    // not being included in the election record, so we infer this data from
    // the first cast ballot.
    let contestInfoArray: VContestInfo[] = []
    if (this.election.cast_ballots.length > 0) {
      contestInfoArray = this.election.cast_ballots[0].contests.map(
        (contest) =>
          new VContestInfo(contest.selections.length, contest.max_selections)
      )
    }

    // Initialize and verify cast ballots
    if (!isError(jointPublicKey)) {
      const vCastBallots = this.election.cast_ballots.map(
        (castBallot, index) =>
          new VEncryptedBallotRecord(
            this.context,
            extendedBaseHash,
            castBallot,
            contestInfoArray,
            jointPublicKey,
            index
          )
      )
      vCastBallots.map((vCastBallot) => vCastBallot.verify(recorder))
    }

    const publicKeys = vCoefficients.map(
      (commitments) => commitments.firstCoefficientElement
    )
    const vContestTallies = this.election.contest_tallies.map(
      (tallyDecryption, index) =>
        new VContestTallyRecord(
          this.context,
          extendedBaseHash,
          tallyDecryption,
          this.election.cast_ballots,
          contestInfoArray,
          publicKeys,
          index
        )
    )

    vContestTallies.map((vContestTally) => vContestTally.verify(recorder))

    const vSpoiledBallots = this.election.spoiled_ballots.map(
      (spoiledBallot, index) =>
        new VSpoiledBallotRecord(
          this.context,
          extendedBaseHash,
          spoiledBallot.contests,
          contestInfoArray,
          publicKeys,
          index
        )
    )

    // Note that we can't verify spoiled ballots encryption proofs because
    // they are not currently being included in the election record
    vSpoiledBallots.map((spoiled) => spoiled.verify(recorder))
  }
}

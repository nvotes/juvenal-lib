import * as fs from 'fs'
import { exitError } from '../src/errors'
import { verifyElectionRecord } from '../src/verify'
import { VRecorder } from '../src/recorders/VRecorder'

export interface Verification {
  status: boolean
  context: string[]
  name: string
  title: string
}

/**
 * Records in an array all the errors in verifications so that one can
 * afterwards check if those were as expected.
 */
export class ArrayRecorder implements VRecorder {
  errors: Verification[] = []
  hasFailures = false

  record(
    status: boolean,
    context: string[],
    name: string,
    title: string
  ): void {
    this.hasFailures = this.hasFailures || !status

    if (!status) {
      this.errors.push({
        status: status,
        context: context,
        name: name,
        title: title
      })
    }
  }
}

function checkErrors(electionRecordPath: string, errors: Verification[]) {
  const data = fs.readFileSync(electionRecordPath, 'utf8')
  const recorder = new ArrayRecorder()
  verifyElectionRecord(data, exitError, recorder)
  expect(recorder.errors).toEqual(errors)
}

/*describe('Verify pregenerated election records', () => {
  test('tests/data/valid_encrypted.json records no errors', () => {
    checkErrors('tests/data/valid_encrypted.json', [])
  })

  test('tests/data/invalid_three_different_broken_proofs.json records appropiate errors', () => {
    checkErrors('tests/data/invalid_three_different_broken_proofs.json', [
      {
        status: false,
        context: ['Election', 'Tally, contest #0', 'Selection #0', 'Share #0'],
        name: 'ChaumPedersenProof',
        title: 'The Chaum-Pedersen proof of share correctness should verify'
      },
      {
        status: false,
        context: ['Election', 'Tally, contest #2', 'Selection #2', 'Share #0'],
        name: 'ChaumPedersenProof',
        title: 'The Chaum-Pedersen proof of share correctness should verify'
      },
      {
        status: false,
        context: [
          'Election',
          'Spoiled ballot #0',
          'Contest #2',
          'Selection #2',
          'Share #3'
        ],
        name: 'ShareLoading',
        title: 'Error converting share: Not a quadratic residue!'
      },
      {
        status: false,
        context: [
          'Election',
          'Spoiled ballot #0',
          'Contest #2',
          'Selection #2'
        ],
        name: 'SharesLoading',
        title: 'Not all shares were loaded correctly'
      }
    ])
  })
})*/

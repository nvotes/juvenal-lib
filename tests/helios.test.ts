import { arithm, crypto, util, eio } from '../vendors/vjsc/vjsc-1.1.1.js'
import * as fs from 'fs'
import {
  strDecToByteArray,
  strDecToHex,
  isError,
  firstError
} from '../src/crypto/utils'
import { SchnorrProofHelios } from '../src/crypto/SchnorrProofHelios'
import { SigmaProofOr } from '../src/crypto/SigmaProofOr'

// Helios json data
let election: any
let ballot: any
let trustees: any

// global variables
let labelBytes: Uint8Array
let pGroup: arithm.ModPGroup
let publicKey: arithm.ModPGroupElement
let ppGroup: arithm.PPGroup

function readData(): void {
  election = JSON.parse(
    fs.readFileSync('tests/data/helios_election.json', 'utf8')
  )
  ballot = JSON.parse(fs.readFileSync('tests/data/helios_ballot.json', 'utf8'))
  trustees = JSON.parse(
    fs.readFileSync('tests/data/helios_trustees.json', 'utf8')
  )
  labelBytes = strDecToByteArray('')
  const publicKeyObj = election.public_key
  const pValue = new arithm.LargeInteger(strDecToHex(publicKeyObj.p))
  const qValue = new arithm.LargeInteger(strDecToHex(publicKeyObj.q))
  const gValue = new arithm.LargeInteger(strDecToHex(publicKeyObj.g))
  const yValue = strDecToByteArray(publicKeyObj.y)
  pGroup = new arithm.ModPGroup(pValue, qValue, gValue, 1)
  ppGroup = new arithm.PPGroup([pGroup, pGroup])
  publicKey = pGroup.toElement(yValue)
}

beforeAll(() => {
  return readData()
})

describe('Verify pregenerated helios data', () => {
  test('election public key constructed correctly', () => {
    const pk1 = trustees[0].public_key.y
    const pk2 = trustees[1].public_key.y

    const pk1b = strDecToByteArray(pk1)
    const pk2b = strDecToByteArray(pk2)

    const pk1e = pGroup.toElement(pk1b)
    const pk2e = pGroup.toElement(pk2b)

    expect(pk1e.mul(pk2e).equals(publicKey)).toBe(true)
  })

  test('individual choice disjunctive (CDS) proof', () => {
    const answers = ballot.vote.answers
    const alphab = strDecToByteArray(answers[0].choices[0].alpha)
    const betab = strDecToByteArray(answers[0].choices[0].beta)

    const challenge1b = strDecToByteArray(
      answers[0].individual_proofs[0][0].challenge
    )
    const response1b = strDecToByteArray(
      answers[0].individual_proofs[0][0].response
    )
    const challenge2b = strDecToByteArray(
      answers[0].individual_proofs[0][1].challenge
    )
    const response2b = strDecToByteArray(
      answers[0].individual_proofs[0][1].response
    )

    const commitment11b = strDecToByteArray(
      answers[0].individual_proofs[0][0].commitment.A
    )
    const commitment12b = strDecToByteArray(
      answers[0].individual_proofs[0][0].commitment.B
    )
    const commitment21b = strDecToByteArray(
      answers[0].individual_proofs[0][1].commitment.A
    )
    const commitment22b = strDecToByteArray(
      answers[0].individual_proofs[0][1].commitment.B
    )

    const g1 = pGroup.getg()
    const g2 = publicKey

    const pairCDS = ppGroup.prod([g1, g2])
    const ehCds = new arithm.ExpHom(pGroup.pRing, pairCDS)
    const sps: SchnorrProofHelios[] = []
    sps[0] = new SchnorrProofHelios(ehCds)
    sps[1] = new SchnorrProofHelios(ehCds)

    const cds = new SigmaProofOr(pGroup.pRing, sps)
    const alphae = pGroup.toElement(alphab)
    const betae = pGroup.toElement(betab)

    const instances: arithm.PPGroupElement[] = []

    instances[0] = ppGroup.prod([alphae, betae])
    instances[1] = ppGroup.prod([alphae, betae.mul(g1.inv())])

    const commitments = []
    commitments[0] = new eio.ByteTree([
      eio.ByteTree.asByteTree(commitment11b),
      eio.ByteTree.asByteTree(commitment12b)
    ])
    commitments[1] = new eio.ByteTree([
      eio.ByteTree.asByteTree(commitment21b),
      eio.ByteTree.asByteTree(commitment22b)
    ])

    const responses = []
    responses[0] = new eio.ByteTree([
      eio.ByteTree.asByteTree(challenge1b),
      eio.ByteTree.asByteTree(challenge2b)
    ])
    responses[1] = new eio.ByteTree([
      eio.ByteTree.asByteTree(response1b),
      eio.ByteTree.asByteTree(response2b)
    ])

    const proof = new eio.ByteTree([
      new eio.ByteTree(commitments),
      new eio.ByteTree(responses)
    ])

    const okCds = cds.verify(
      labelBytes,
      instances,
      crypto.sha256,
      proof.toByteArray()
    )
    expect(okCds).toBe(true)
  })
})

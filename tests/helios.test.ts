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

  test('vector choice disjunctive (CDS) proof', () => {
    const choices = ballot.vote.answers[1].choices

    const elements = choices.map((x: any) => {
      const a = strDecToByteArray(x.alpha)
      const b = strDecToByteArray(x.beta)
      return ppGroup.prod([pGroup.toElement(a), pGroup.toElement(b)])
    })

    const sum: arithm.PPGroupElement = elements.reduce(
      (
        encryptedSum: arithm.PPGroupElement,
        ciphertext: arithm.PPGroupElement
      ) => encryptedSum.mul(ciphertext),
      ppGroup.getONE()
    )

    const op = ballot.vote.answers[1].overall_proof

    const g1 = pGroup.getg()
    const g2 = publicKey
    const pairCDS = ppGroup.prod([g1, g2])
    const ehCds = new arithm.ExpHom(pGroup.pRing, pairCDS)
    const minimum = 1
    const oSps: SchnorrProofHelios[] = []
    const oInstances: arithm.PPGroupElement[] = []
    const oCommitments: eio.ByteTree[] = []
    const oChallenges: eio.ByteTree[] = []
    const oResponses: eio.ByteTree[] = []

    op.forEach((proof: any, index: number) => {
      oSps.push(new SchnorrProofHelios(ehCds))
      const exp = new arithm.LargeInteger('' + (index + minimum))
      const instance = ppGroup.prod([
        sum.project(0),
        sum.project(1).mul(g1.inv().exp(exp))
      ])
      oInstances.push(instance)
      const c1 = util.hexToByteArray(BigInt(proof.commitment.A).toString(16))
      const c2 = util.hexToByteArray(BigInt(proof.commitment.B).toString(16))
      oCommitments.push(
        new eio.ByteTree([
          eio.ByteTree.asByteTree(c1),
          eio.ByteTree.asByteTree(c2)
        ])
      )
      const ch = util.hexToByteArray(BigInt(proof.challenge).toString(16))
      oChallenges.push(eio.ByteTree.asByteTree(ch))
      const r = util.hexToByteArray(BigInt(proof.response).toString(16))
      oResponses.push(eio.ByteTree.asByteTree(r))
    })

    const responses = []
    responses[0] = new eio.ByteTree(oChallenges)
    responses[1] = new eio.ByteTree(oResponses)

    const oCds = new SigmaProofOr(pGroup.pRing, oSps)
    const oProof = new eio.ByteTree([
      new eio.ByteTree(oCommitments),
      new eio.ByteTree(responses)
    ])
    const allOk = oCds.verify(
      labelBytes,
      oInstances,
      crypto.sha256,
      oProof.toByteArray()
    )

    expect(allOk).toBe(true)
  })
})

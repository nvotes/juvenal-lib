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
var election: any
var ballot: any
var trustees: any

// global variables
var labelBytes: Uint8Array
var p_group: arithm.ModPGroup
var publicKey: arithm.ModPGroupElement
var ppGroup: arithm.PPGroup


function readData(): void {
  election = JSON.parse(fs.readFileSync('tests/data/helios_election.json', 'utf8'))
  ballot = JSON.parse(fs.readFileSync('tests/data/helios_ballot.json', 'utf8'))
  trustees = JSON.parse(fs.readFileSync('tests/data/helios_trustees.json', 'utf8'))
  labelBytes = strDecToByteArray("")
  const public_key = election['public_key']
  const p_value = new arithm.LargeInteger(strDecToHex(public_key.p))
  const q_value = new arithm.LargeInteger(strDecToHex(public_key.q))
  const g_value = new arithm.LargeInteger(strDecToHex(public_key.g))
  const y_value = strDecToByteArray(public_key.y)
  p_group = new arithm.ModPGroup(
      p_value,
      q_value,
      g_value,
      1
    )
  ppGroup = new arithm.PPGroup([p_group, p_group])
  publicKey = p_group.toElement(y_value)
}

beforeAll(() => {
  return readData();
});

describe('Verify pregenerated helios data', () => {
  test('election public key constructed correctly', () => {
    
    const pk1 = trustees[0].public_key.y
    const pk2 = trustees[1].public_key.y

    const pk1b = strDecToByteArray(pk1)
    const pk2b = strDecToByteArray(pk2)

    const pk1e = p_group.toElement(pk1b)
    const pk2e = p_group.toElement(pk2b)

    expect(pk1e.mul(pk2e).equals(publicKey)).toBe(true)
  })

  test('individual choice disjunctive (CDS) proof', () => {
    
    const answers = ballot.vote.answers
    const alphab = strDecToByteArray(answers[0].choices[0].alpha)
    const betab = strDecToByteArray(answers[0].choices[0].beta)

    const challenge1b = strDecToByteArray(answers[0].individual_proofs[0][0].challenge)
    const response1b = strDecToByteArray(answers[0].individual_proofs[0][0].response)
    const challenge2b = strDecToByteArray(answers[0].individual_proofs[0][1].challenge)
    const response2b = strDecToByteArray(answers[0].individual_proofs[0][1].response)

    const commitment11b = strDecToByteArray(answers[0].individual_proofs[0][0].commitment.A)
    const commitment12b = strDecToByteArray(answers[0].individual_proofs[0][0].commitment.B)
    const commitment21b = strDecToByteArray(answers[0].individual_proofs[0][1].commitment.A)
    const commitment22b = strDecToByteArray(answers[0].individual_proofs[0][1].commitment.B)
    
    const g1 = p_group.getg()
    const g2 = publicKey

    const pairCDS = ppGroup.prod([g1, g2])
    const ehCds = new arithm.ExpHom(p_group.pRing, pairCDS)
    const sps: SchnorrProofHelios[] = []
    sps[0] = new SchnorrProofHelios(ehCds)
    sps[1] = new SchnorrProofHelios(ehCds)

    const cds = new SigmaProofOr(p_group.pRing, sps)
    const alphae = p_group.toElement(alphab)
    const betae = p_group.toElement(betab)

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

    const proof = new eio.ByteTree([new eio.ByteTree(commitments), new eio.ByteTree(responses)])

    const okCds = cds.verify(labelBytes, instances, crypto.sha256, proof.toByteArray())
    expect(okCds).toBe(true)
  })
})
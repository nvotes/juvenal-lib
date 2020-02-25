import { arithm, crypto, util } from '../vendors/vjsc/vjsc-1.1.1.js'
import * as fs from 'fs'
import {
  strDecToByteArray,
  strDecToHex,
  isError,
  firstError
} from '../src/crypto/utils'

// Helios json data
var election: any
var ballot: any
var trustees: any

// test global variables
var labelBytes: Uint8Array
var p_group: arithm.ModPGroup
var publicKey: arithm.ModPGroupElement


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
})
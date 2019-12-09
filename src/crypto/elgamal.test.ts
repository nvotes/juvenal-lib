import { arithm, crypto, util } from '../../vendors/vjsc/vjsc-1.1.1.js'
import * as elgamal from './elgamal'

describe('Tests related to VJSC', () => {
  const groupName = 'modp2048'
  let params: string[]
  let group: arithm.ModPGroup
  let generatorLI: arithm.LargeInteger
  let g1: arithm.ModPGroupElement
  let order: arithm.LargeInteger
  let randomSource: crypto.RandomDevice
  const statDist = 50
  let pPGroup: arithm.PPGroup
  let label: Uint8Array

  beforeAll(() => {
    params = arithm.ModPGroup.getParams(groupName)
    group = arithm.ModPGroup.getPGroup(groupName)
    pPGroup = new arithm.PPGroup([group, group])

    const gString: string = arithm.ModPGroup.getParams(groupName)[1]
    generatorLI = new arithm.LargeInteger(gString)

    g1 = group.getg()
    order = group.getElementOrder()
    randomSource = new crypto.RandomDevice()
    label = randomSource.getBytes(10)
  })

  // Test that a joint public key is the multiplicative sum of the given
  // keys
  test('createJointPublicKey', () => {
    // An empty list of joint public keys should be equal to number one
    expect(elgamal.createJointPublicKey([], group).equals(group.getONE())).toBe(
      true
    )

    // The joint public key of any single element should be equal to itself
    const publicKeysG: arithm.ModPGroupElement[] = [
      group.getg().exp(new arithm.LargeInteger('8754'))
    ]
    expect(
      elgamal.createJointPublicKey(publicKeysG, group).equals(publicKeysG[0])
    ).toBe(true)

    // g^a * g^b * g^c (mod p) == g^(a+b+c) (mod p)
    const publicKeysSum: arithm.ModPGroupElement[] = [
      group.getg().exp(new arithm.LargeInteger('1')),
      group.getg().exp(new arithm.LargeInteger('2')),
      group.getg().exp(new arithm.LargeInteger('3'))
    ]
    expect(
      elgamal
        .createJointPublicKey(publicKeysSum, group)
        .equals(group.getg().exp(new arithm.LargeInteger('6')))
    ).toBe(true)

    // test that different order should not change the result
    // g^a * g^b * g^c (mod p) == g^(a+b+c) (mod p)
    const publicKeysSum2: arithm.ModPGroupElement[] = [
      group.getg().exp(new arithm.LargeInteger('2')),
      group.getg().exp(new arithm.LargeInteger('3')),
      group.getg().exp(new arithm.LargeInteger('1'))
    ]
    expect(
      elgamal
        .createJointPublicKey(publicKeysSum2, group)
        .equals(group.getg().exp(new arithm.LargeInteger('6')))
    ).toBe(true)
  })

  // Test that the sum of elgamal pairs work as expected
  test('sum', () => {
    const ppGroup = new arithm.PPGroup([group, group])

    // An empty list if equal to the group's identity element
    expect(elgamal.sum([], ppGroup).equals(ppGroup.getONE())).toBe(true)

    const singlePair = [
      ppGroup.prod([
        group.getg().exp(new arithm.LargeInteger('2')),
        group.getg().exp(new arithm.LargeInteger('4'))
      ])
    ]

    // A list with a single pair is equal to the pair itself
    expect(elgamal.sum(singlePair, ppGroup).equals(singlePair[0])).toBe(true)

    const threePairs = [
      ppGroup.prod([
        group.getg().exp(new arithm.LargeInteger('1')),
        group.getg().exp(new arithm.LargeInteger('4'))
      ]),
      ppGroup.prod([
        group.getg().exp(new arithm.LargeInteger('2')),
        group.getg().exp(new arithm.LargeInteger('5'))
      ]),
      ppGroup.prod([
        group.getg().exp(new arithm.LargeInteger('3')),
        group.getg().exp(new arithm.LargeInteger('6'))
      ])
    ]

    // the result is the multiplicative sum of the pairs
    const threePairsSum = ppGroup.prod([
      group.getg().exp(new arithm.LargeInteger('6')), // 1+2+3 = 6
      group.getg().exp(new arithm.LargeInteger(BigInt(15).toString(16))) // 4+5+6 = 15
    ])
    expect(elgamal.sum(threePairs, ppGroup).equals(threePairsSum)).toBe(true)

    // order of the pairs does not alter the result
    const threePairs2 = [threePairs[1], threePairs[2], threePairs[0]]
    expect(elgamal.sum(threePairs2, ppGroup).equals(threePairsSum)).toBe(true)
  })
})

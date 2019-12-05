import { arithm, crypto, util } from '../vendors/vjsc/vjsc-1.1.1.js'
import { typeParameterInstantiation } from '@babel/types'

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

  test('Encryption params to be loaded correctly', () => {
    expect(g1.exp(order).equals(group.getONE())).toBe(true)
  })

  test('Schnorr as generalized SigmaProof', () => {
    const eh = new arithm.ExpHom(group.pRing, group.getg())
    const sp = new crypto.SchnorrProof(eh)
    const witness: arithm.PRingElement = eh.domain.randomElement(
      randomSource,
      statDist
    )
    const instance: arithm.PGroupElement = eh.eva(witness)

    const proof = sp.prove(
      label,
      instance,
      witness,
      crypto.sha256,
      randomSource,
      50
    )
    const ok = sp.verify(label, instance, crypto.sha256, proof)
    expect(ok).toBe(true)
  })

  test('Chaum-Pedersen as generalized SigmaProof using Schnorr class', () => {
    const t = group.pRing.randomElement(randomSource, statDist)
    const c = group.getg().exp(t)

    const s = group.pRing.randomElement(randomSource, statDist)
    const d = group.getg().exp(s)

    const b = pPGroup.prod([c, d])

    // eh(x) = (c^x, d^x)
    const eh = new arithm.ExpHom(group.pRing, b)
    const sp = new crypto.SchnorrProof(eh)
    const witness = eh.domain.randomElement(randomSource, statDist)
    const instance = eh.eva(witness)
    const proof = sp.prove(
      label,
      instance,
      witness,
      crypto.sha256,
      randomSource,
      50
    )
    const ok = sp.verify(label, instance, crypto.sha256, proof)
    expect(ok).toBe(true)
  })

  test('Chaum-Pedersen + Cramer-Damgard-Schoenmakers', () => {
    // TODO: check with Douglas

    const sps: crypto.SchnorrProof[] = []
    const witnesses: arithm.PRingElement[] = []
    const instances: arithm.PGroupElement[] = []

    const correct = 0

    const t = group.pRing.randomElement(randomSource, statDist)
    const c = group.getg().exp(t)

    const s = group.pRing.randomElement(randomSource, statDist)
    const d = group.getg().exp(s)

    const b = pPGroup.prod([c, d])
    const eh: arithm.ExpHom = new arithm.ExpHom(group.pRing, b)

    for (let j = 0; j < 2; j++) {
      // eh(x) = (c^x, d^x)
      sps[j] = new crypto.SchnorrProof(eh)
      witnesses[j] = eh.domain.randomElement(randomSource, statDist)
      if (j == correct) {
        instances[j] = eh.eva(witnesses[j])
      } else {
        const fake = eh.domain.randomElement(randomSource, statDist)
        instances[j] = eh.eva(fake)
      }
    }

    const sp = new crypto.SigmaProofOr(group.pRing, sps)
    const proof = sp.prove(
      label,
      instances,
      [witnesses[correct], correct],
      crypto.sha256,
      randomSource,
      50
    )
    let ok = sp.verify(label, instances, crypto.sha256, proof)

    expect(ok).toBe(true)

    const badWitness = eh.domain.randomElement(randomSource, statDist)
    const invalidProof = sp.prove(
      label,
      instances,
      [badWitness, correct],
      crypto.sha256,
      randomSource,
      50
    )
    ok = sp.verify(label, instances, crypto.sha256, invalidProof)
    expect(ok).toBe(false)
  })

  test('Threshold Cryptosystem', () => {
    const n = 5
    const k = 3

    class Trustee {
      numTrustees: number
      threshold: number
      coefficients: arithm.PRingElement[] = []
      commitments: arithm.ModPGroupElement[] = []
      shares: arithm.PRingElement[] = []
      externalShares: arithm.PRingElement[] = []

      // A degree n polynomial is uniquely determined by n + 1 points
      // Therefore necessary threshold = n + 1, so degree = threshold - 1
      // Therefore number of coefficients = threshold (degree n has n + 1 coefficients)
      constructor(numTrustees: number, threshold: number) {
        this.numTrustees = numTrustees
        this.threshold = threshold

        for (let i = 0; i < threshold; i++) {
          this.coefficients[i] = group.pRing.randomElement(
            randomSource,
            statDist
          )
          this.commitments[i] = group.getg().exp(this.coefficients[i])
        }
        for (let i = 0; i < numTrustees; i++) {
          this.shares[i] = this.evalPoly(i + 1)
        }
      }
      private evalPoly(trustee: number): arithm.PRingElement {
        let sum = this.coefficients[0]
        const trusteeInt = new arithm.LargeInteger(trustee.toString())
        let power = group.pRing.getONE()

        for (let i = 1; i < this.threshold; i++) {
          power = power.mul(trusteeInt)
          sum = sum.add(this.coefficients[i].mul(power))
        }

        return sum
      }

      static lagrange(trustee: number, present: number[]): arithm.PRingElement {
        let numerator = group.pRing.getONE()
        let denominator = group.pRing.getONE()
        const trusteeInt = new arithm.LargeInteger(trustee.toString())

        for (let i = 0; i < present.length; i++) {
          if (present[i] == trustee) {
            continue
          }
          const presentInt = new arithm.LargeInteger(present[i].toString())
          const diffInt = new arithm.LargeInteger(
            (present[i] - trustee).toString()
          )
          numerator = numerator.mul(presentInt)
          denominator = denominator.mul(diffInt)
        }

        return numerator.mul(denominator.inv())
      }
    }

    const trustees: Trustee[] = []
    let pk: arithm.ModPGroupElement = group.getONE()
    for (let i = 0; i < n; i++) {
      trustees[i] = new Trustee(n, k)
      pk = pk.mul(trustees[i].commitments[0])
    }
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if (i == j) {
          continue
        }
        trustees[j].externalShares[i] = trustees[i].shares[j]
      }
    }

    const pkGroup = new arithm.PPGroup([group, group])
    const publicKey = pkGroup.prod([group.getg(), pk])

    const messageString = 'Hello World'
    const messageBytes: Uint8Array = util.asciiToByteArray(messageString)
    const message: arithm.ModPGroupElement = group.encode(
      messageBytes,
      0,
      messageBytes.length
    )
    const elgamal: crypto.ElGamal = new crypto.ElGamal(
      true,
      group,
      randomSource,
      statDist
    )
    const encrypted: arithm.PPGroupElement = elgamal.encrypt(publicKey, message)

    // all trustees present

    const alpha: arithm.ModPGroupElement = encrypted.project(
      0
    ) as arithm.ModPGroupElement
    const beta: arithm.ModPGroupElement = encrypted.project(
      1
    ) as arithm.ModPGroupElement
    let divider: arithm.ModPGroupElement = group.getONE()
    for (let i = 0; i < n; i++) {
      divider = divider.mul(alpha.exp(trustees[i].coefficients[0]))
    }
    let decryption: arithm.ModPGroupElement = beta.mul(divider.inv())
    let decryptedBytes = new Uint8Array(messageBytes.length)
    decryption.decode(decryptedBytes, 0)

    let decryptedString = util.byteArrayToAscii(decryptedBytes)
    expect(messageString).toBe(decryptedString)

    // threshold decryption

    const present = [1, 4, 5]
    const missing = [2, 3]

    const dividers: arithm.ModPGroupElement[] = util.fill(group.getONE(), n)
    const lagranges: arithm.PRingElement[] = new Array<arithm.PRingElement>(n)

    for (let i = 0; i < present.length; i++) {
      dividers[present[i] - 1] = alpha.exp(
        trustees[present[i] - 1].coefficients[0]
      )
      lagranges[present[i] - 1] = Trustee.lagrange(present[i], present)
    }

    for (let j = 0; j < missing.length; j++) {
      for (let i = 0; i < present.length; i++) {
        const nextShare =
          trustees[present[i] - 1].externalShares[missing[j] - 1]
        dividers[missing[j] - 1] = dividers[missing[j] - 1].mul(
          alpha.exp(nextShare).exp(lagranges[present[i] - 1])
        )
      }
    }

    divider = group.getONE()
    for (let i = 0; i < n; i++) {
      divider = divider.mul(dividers[i])
    }

    decryption = beta.mul(divider.inv())
    decryptedBytes = new Uint8Array(messageBytes.length)
    decryption.decode(decryptedBytes, 0)

    decryptedString = util.byteArrayToAscii(decryptedBytes)
    expect(messageString).toBe(decryptedString)
  })
})

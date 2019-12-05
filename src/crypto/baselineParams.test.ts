import { arithm } from '../../vendors/vjsc/vjsc-1.1.1'
import { baselineParameters } from './baselineParams'

/// Order q multiplicative subgroup of Z^*_p (Gq) as specified in the
/// [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// It is the largest 256-bit prime such as:
///
/// q = 2^256 - 189
///
/// Here we verify that formula
test('verifyPrimeQ', () => {
  const q = baselineParameters.getElementOrder()
  const qCalculated = new arithm.LargeInteger(
    (BigInt(2) ** BigInt(256) - BigInt(189)).toString(16)
  )

  expect(q.equals(qCalculated)).toBe(true)
})

/// Modulus p of the multiplicative subgroup of Z^*_p (Gq) as specified
/// in the [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// The modulus p is set to be the largest 4096-bit prime which is one
/// greater than a multiple of q. This works out to:
///
/// p = 2^4096 - 69*q - 2650872664557734482243044168410288960
///
/// Here we verify that formula
test('verifyPrimeP', () => {
  const q = BigInt('0x' + baselineParameters.getElementOrder().toHexString())
  const pCalculated = new arithm.LargeInteger(
    (
      BigInt(2) ** BigInt(4096) -
      BigInt(69) * q -
      BigInt('2650872664557734482243044168410288960')
    ).toString(16)
  )

  expect(baselineParameters.modulus.equals(pCalculated)).toBe(true)
})

/// Generator G of the multiplicative subgroup of Z^*_p (Gq) as specified
/// in the [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// The value of the cofactor r is set to "r = (p−1) / q" and the generator
/// g is:
///
/// g = 2^r (mod p)
///
/// Here we verify that formula
test('verifyGeneratorG', () => {
  const q = baselineParameters.getElementOrder()
  const p = baselineParameters.modulus
  const r = p.sub(arithm.LargeInteger.ONE).div(q)
  const calculatedG = new arithm.LargeInteger('2').modPow(r, p)

  expect(baselineParameters.getg().value.equals(calculatedG)).toBe(true)
})

import { arithm, crypto, util } from '../../vendors/vjsc/vjsc-1.1.1';
import { str_dec_to_hex, remove_spaces } from './utils';
import { baseline_parameters } from './baseline_params';

/// Order q multiplicative subgroup of Z^*_p (Gq) as specified in the 
/// [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// It is the largest 256-bit prime such as:
///
/// q = 2^256 - 189
///
/// Here we verify that formula
test('verify_prime_q', () => {
    let q = baseline_parameters.getElementOrder();
    let q_calculated = new arithm.LargeInteger(
        (BigInt(2) ** BigInt(256) - BigInt(189)).toString(16)
    );

    expect(q.equals(q_calculated)).toBe(true);
  });
  
/// Modulus p of the multiplicative subgroup of Z^*_p (Gq) as specified 
/// in the [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// The modulus p is set to be the largest 4096-bit prime which is one 
/// greater than a multiple of q. This works out to:
///
/// p = 2^4096 - 69*q - 2650872664557734482243044168410288960
///
/// Here we verify that formula
test('verify_prime_p', () => {
    let q = BigInt("0x"+baseline_parameters.getElementOrder().toHexString());
    let p_calculated = new arithm.LargeInteger(
        (
            BigInt(2) ** BigInt(4096) 
            - BigInt(69) * q
            - BigInt("2650872664557734482243044168410288960")
        )
        .toString(16)
    );

    expect(baseline_parameters.modulus.equals(p_calculated)).toBe(true);
  });

/// Generator G of the multiplicative subgroup of Z^*_p (Gq) as specified 
/// in the [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// The value of the cofactor r is set to "r = (p−1) / q" and the generator
/// g is:
///
/// g = 2^r (mod p)
///
/// Here we verify that formula
test('verify_generator_g', () => {
    let q = baseline_parameters.getElementOrder();
    let p = baseline_parameters.modulus;
    let r = p.sub(arithm.LargeInteger.ONE).div(q);
    let calculated_g = new arithm.LargeInteger("2").modPow(r, p);

    expect(baseline_parameters.getg().value.equals(calculated_g)).toBe(true);
  });
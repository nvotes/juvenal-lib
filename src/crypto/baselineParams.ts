import { arithm } from '../../vendors/vjsc/vjsc-1.1.1';
import { removeSpaces } from './utils';

/// Order q multiplicative subgroup of Z^*_p (Gq) as specified in the 
/// [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// It is the largest 256-bit prime such as:
///
/// q = 2^256 - 189
///
/// We check that that formula in unit test "verifyPrimeQ".
export const PRIME_Q_HEX = 
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43";

/// Modulus p of the multiplicative subgroup of Z^*_p (Gq) as specified 
/// in the [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// The modulus p is set to be the largest 4096-bit prime which is one 
/// greater than a multiple of q. This works out to:
///
/// p = 2^4096 - 69*q - 2650872664557734482243044168410288960
///
/// We check that that formula in unit test "verifyPrimeP".
export const PRIME_P_HEX = 
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFBA" +
"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FE0175E3 0B1B0E79 1DB50299 4F24DFB1";

/// Generator G of the multiplicative subgroup of Z^*_p (Gq) as specified 
/// in the [ElectionGuard specification (V0.85)](https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf).
/// The value of the cofactor r is set to "r = (p−1) / q" and the generator
/// g is:
///
/// g = 2^r (mod p)
///
/// We check that that formula in unit test "verifyGeneratorG".
export const GENERATOR_G_HEX = 
"9B61C275 E06F3E38 372F9A9A DE0CDC4C 82F4CE53 37B3EF0E D28BEDBC 01342EB8" +
"9977C811 6D741270 D45B0EBE 12D96C5A EE997FEF DEA18569 018AFE12 84E702BB" +
"9B8C78E0 3E697F37 8D25BCBC B94FEFD1 2B7F9704 7F634232 68881C3B 96B389E1" +
"34CB3162 CB73ED80 52F7946C 7E72907F D8B96862 D443B5C2 6F7B0E3F DC9F035C" +
"BF0F5AAB 670B7901 1A8BCDEB CF421CC9 CBBE12C7 88E50328 041EB59D 81079497" +
"B667B960 49DA04C7 9D60F527 B1C02F7E CBA66849 179CB5CF BE7C990C D888B69C" +
"44171E4F 54C21A8C FE9D821F 195F7553 B73A7057 07263EAE A3B7AFA7 DED79ACF" +
"5A64F3BF B939B815 C52085F4 0714F4C6 460B0B0C 3598E317 46A06C2A 3457676C" +
"B345C8A3 90EBB942 8CEECEFA 6FCB1C27 A9E527A6 C55B8D6B 2B1868D6 EC719E18" +
"9A799605 C540F864 1F135D5D C7FB62D5 8E0DE0B6 AE3AB90E 91FB9965 05D7D928" +
"3DA833FF 0CB6CC8C A7BAFA0E 90BB1ADB 81545A80 1F0016DC 7088A4DF 2CFB7D6D" +
"D876A2A5 807BDAA4 000DAFA2 DFB6FBB0 ED9D7755 89156DDB FC24FF22 03FFF9C5" +
"CF7C85C6 8F66DE94 C98331F5 0FEF59CF 8E7CE9D9 5FA008F7 C1672D26 9C163751" +
"012826C4 C8F5B5F4 C11EDB62 550F3CF9 3D86F3CC 6E22B0E7 69AC6591 57F40383" +
"B5DF9DB9 F8414F6C B5FA7D17 BDDD3BC9 0DC7BDC3 9BAF3BE6 02A99E2A 37CE3A5C" +
"098A8C1E FD3CD28A 6B79306C A2C20C55 174218A3 935F697E 813628D2 D861BE54";

/**
 * These are the baseline parameters, defined in ElectionGuard spec.
 */
export const baselineParameters: arithm.ModPGroup = new arithm.ModPGroup(
    new arithm.LargeInteger(removeSpaces(PRIME_P_HEX)),
    new arithm.LargeInteger(removeSpaces(PRIME_Q_HEX)),
    new arithm.LargeInteger(removeSpaces(GENERATOR_G_HEX)),
    1 // encoding=1 means 'safe prime encoding'
);
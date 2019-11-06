import { arithm, crypto, util } from '../vendors/vjsc/vjsc-1.1.1.js'

describe('Tests related to VJSC', () => {
  
  let groupName: string = 'modp2048';
  let params: string[];
  let group: arithm.ModPGroup;
  let generatorLI: arithm.LargeInteger;
  let g1: arithm.ModPGroupElement;
  let order: arithm.LargeInteger;
  let randomSource: crypto.RandomDevice;
  let statDist = 50;
  let pPGroup: arithm.PPGroup;
  let label: Uint8Array;

  beforeAll(() => {
    params = arithm.ModPGroup.getParams(groupName);
    group = arithm.ModPGroup.getPGroup(groupName);
    pPGroup = new arithm.PPGroup([group, group]);

    let gString: string = arithm.ModPGroup.getParams(groupName)[1];
    generatorLI = new arithm.LargeInteger(gString);

    g1 = group.getg();
    order = group.getElementOrder();
    randomSource = new crypto.RandomDevice();
    label = randomSource.getBytes(10);
  });

  test('Encryption params to be loaded correctly', () => {
    expect(g1.exp(order).equals(group.getONE())).toBe(true);
  });

  test('Schnorr as generalized SigmaProof', () => {
    let eh = new arithm.ExpHom(group.pRing, group.getg());
    let sp = new crypto.SchnorrProof(eh);
    let witness: arithm.PRingElement = eh.domain.randomElement(randomSource, statDist);
    let instance: arithm.PGroupElement = eh.eva(witness);

    let proof = sp.prove(label, instance, witness, crypto.sha256, randomSource, 50);
    let ok = sp.verify(label, instance, crypto.sha256, proof);
    expect(ok).toBe(true);
  });

  test('Chaum-Pedersen as generalized SigmaProof using Schnorr class', () => {
    let t = group.pRing.randomElement(randomSource, statDist);
    var c = group.getg().exp(t);

    let s = group.pRing.randomElement(randomSource, statDist);
    let d = group.getg().exp(s);

    let b = pPGroup.prod([c, d]);

    // eh(x) = (c^x, d^x)
    let eh = new arithm.ExpHom(group.pRing, b);
    let sp = new crypto.SchnorrProof(eh);
    let witness = eh.domain.randomElement(randomSource, statDist);
    let instance = eh.eva(witness);
    let proof = sp.prove(label, instance, witness, crypto.sha256, randomSource, 50);
    let ok = sp.verify(label, instance, crypto.sha256, proof);
    expect(ok).toBe(true);
  });


  test('Chaum-Pedersen + Cramer-Damgard-Schoenmakers', ()=> {
    // TODO: check with Douglas

    let sps: crypto.SchnorrProof[] = [];
    let witnesses: arithm.PRingElement[] = [];
    let instances: arithm.PGroupElement[] = [];

    let correct = 0;

    let t = group.pRing.randomElement(randomSource, statDist);
    var c = group.getg().exp(t);

    let s = group.pRing.randomElement(randomSource, statDist);
    let d = group.getg().exp(s);

    let b = pPGroup.prod([c, d]);
    let eh: arithm.ExpHom = new arithm.ExpHom(group.pRing, b);

    for (let j = 0; j < 2; j++) {
        // eh(x) = (c^x, d^x)
        sps[j] = new crypto.SchnorrProof(eh);
        witnesses[j] =
            eh.domain.randomElement(randomSource, statDist);
        if(j == correct) {
            instances[j] = eh.eva(witnesses[j]);
        }
        else {
            let fake = eh.domain.randomElement(randomSource, statDist);
            instances[j] = eh.eva(fake);
        }
    }

    let sp = new crypto.SigmaProofOr(group.pRing, sps);
    let proof = sp.prove(label, instances, [witnesses[correct], correct],
        crypto.sha256, randomSource, 50)
    let ok = sp.verify(label, instances, crypto.sha256, proof);
    
    expect(ok).toBe(true);

    let badWitness = eh.domain.randomElement(randomSource, statDist) 
    let invalidProof = sp.prove(label, instances, [badWitness, correct],
        crypto.sha256, randomSource, 50)
    ok = sp.verify(label, instances, crypto.sha256, invalidProof)
    expect(ok).toBe(false);
  });

  test('Threshold Cryptosystem', () => {
    let n = 5;
    let k = 3;

    class Trustee {
        numTrustees: number;
        threshold: number;
        coefficients: arithm.PRingElement[] = [];
        commitments: arithm.ModPGroupElement[] = [];
        shares: arithm.PRingElement[] = [];
        externalShares: arithm.PRingElement[] = [];

        // A degree n polynomial is uniquely determined by n + 1 points
        // Therefore necessary threshold = n + 1, so degree = threshold - 1
        // Therefore number of coefficients = threshold (degree n has n + 1 coefficients)
        constructor(numTrustees: number, threshold: number) {
            this.numTrustees = numTrustees;
            this.threshold = threshold;

            for (let i = 0; i < threshold; i++) {
                this.coefficients[i] = group.pRing.randomElement(randomSource, statDist);
                this.commitments[i] =  group.getg().exp(this.coefficients[i]);
            }
            for (let i = 0; i < numTrustees; i++) {
                this.shares[i] = this.evalPoly(i + 1);
            }
        }
        private evalPoly(trustee: number): arithm.PRingElement {
            let sum = this.coefficients[0];
            let trusteeInt = new arithm.LargeInteger(trustee.toString());
            let power = group.pRing.getONE();
            
            for (let i = 1; i < this.threshold; i++) {
                power = power.mul(trusteeInt);
                sum = sum.add(this.coefficients[i].mul(power));
            }

            return sum;
        }

        static lagrange(trustee: number, present: number[]): arithm.PRingElement {
            let numerator = group.pRing.getONE();
            let denominator = group.pRing.getONE();
            let trusteeInt = new arithm.LargeInteger(trustee.toString());

            for(let i = 0; i < present.length; i++) {
                if(present[i] == trustee) {
                  continue;
                }
                let presentInt = new arithm.LargeInteger(present[i].toString());
                let diffInt = new arithm.LargeInteger((present[i] - trustee).toString());
                numerator = numerator.mul(presentInt);
                denominator = denominator.mul(diffInt);
            }

            return numerator.mul(denominator.inv());
        }
    }

    let trustees: Trustee[] = [];
    let pk: arithm.ModPGroupElement = group.getONE();
    for (let i = 0; i < n; i++) {
        trustees[i] = new Trustee(n, k);
        pk = pk.mul(trustees[i].commitments[0]);
    }
    for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
            if(i == j) {
              continue;
            }
            trustees[j].externalShares[i] = trustees[i].shares[j];
        }
    }

    let pkGroup = new arithm.PPGroup([group, group]);
    let publicKey = pkGroup.prod([group.getg(), pk]);

    let messageString = "Hello World";
    let messageBytes: Uint8Array = util.asciiToByteArray(messageString);
    let message: arithm.ModPGroupElement = group.encode(messageBytes, 0, messageBytes.length);
    let elgamal: crypto.ElGamal = new crypto.ElGamal(true, group, randomSource, statDist);
    let encrypted: arithm.PPGroupElement = elgamal.encrypt(publicKey, message);

    // all trustees present

    let alpha: arithm.ModPGroupElement = encrypted.project(0) as arithm.ModPGroupElement;
    let beta: arithm.ModPGroupElement = encrypted.project(1) as arithm.ModPGroupElement;
    let divider: arithm.ModPGroupElement = group.getONE();
    for (let i = 0; i < n; i++) {
        divider = divider.mul(alpha.exp(trustees[i].coefficients[0]));
    }
    let decryption: arithm.ModPGroupElement = beta.mul(divider.inv());
    let decryptedBytes = new Uint8Array(messageBytes.length);
    decryption.decode(decryptedBytes, 0);

    let decryptedString = util.byteArrayToAscii(decryptedBytes) ;
    expect(messageString).toBe(decryptedString);

    // threshold decryption

    let present = [1, 4, 5];
    let missing = [2, 3];

    let dividers: arithm.ModPGroupElement[] = util.fill(group.getONE(), n);
    let lagranges: arithm.PRingElement[] = new Array<arithm.PRingElement>(n);

    for(let i = 0; i < present.length; i++) {
        dividers[present[i] - 1] = alpha.exp(trustees[present[i] - 1].coefficients[0]);
        lagranges[present[i] - 1] = Trustee.lagrange(present[i], present);
    }

    for(let j = 0; j < missing.length; j++) {
        for(let i = 0; i < present.length; i++) {
            let nextShare = trustees[present[i] - 1].externalShares[missing[j] - 1];
            dividers[missing[j] - 1] = dividers[missing[j] - 1].mul(
                alpha.exp(nextShare).exp(lagranges[present[i] - 1])
            );
        }
    }

    divider = group.getONE();
    for(let i = 0; i < n; i++) {
        divider = divider.mul(dividers[i]);
    }

    decryption = beta.mul(divider.inv());
    decryptedBytes = new Uint8Array(messageBytes.length);
    decryption.decode(decryptedBytes, 0);

    decryptedString = util.byteArrayToAscii(decryptedBytes) ;
    expect(messageString).toBe(decryptedString);
  });
});
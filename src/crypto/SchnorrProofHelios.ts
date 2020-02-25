import { arithm, crypto, eio, util } from '../../vendors/vjsc/vjsc-1.1.1'
import { SchnorrProof } from './SchnorrProof'

import * as crypto2 from 'crypto'

export class SchnorrProofHelios extends SchnorrProof {
  constructor(hom: arithm.ExpHom) {
    super(hom)
  }

  challenge(
    first: eio.ByteTree,
    second: crypto.HashFunction
  ): arithm.PRingElement {
    const commitmentsBt = first.value[2] as eio.ByteTree
    const commitments = commitmentsBt.value as Array<eio.ByteTree>

    const cStrings: Array<string> = commitments.map((value: eio.ByteTree) => {
      if (value.value[0] instanceof eio.ByteTree) {
        const pair: Array<eio.ByteTree> = value.value as Array<eio.ByteTree>

        const a = BigInt(
          '0x' + util.byteArrayToHex(pair[0].value as Uint8Array)
        ).toString()

        const b = BigInt(
          '0x' + util.byteArrayToHex(pair[1].value as Uint8Array)
        ).toString()

        return a + ',' + b
      } else {
        return BigInt(
          '0x' + util.byteArrayToHex(value.value as Uint8Array)
        ).toString()
      }
    })

    const all = cStrings.join(',')
    const digest = this.sha1(all)
    const digestBytes = util.hexToByteArray(digest)

    const challenge = this.homomorphism.domain
      .getPField()
      .toElement(digestBytes)

    return challenge
  }

  private sha1(bytes: string): string {
    return crypto2
      .createHash('sha1')
      .update(bytes)
      .digest('hex')
  }
}

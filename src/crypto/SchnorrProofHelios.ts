import { arithm, crypto, eio, util } from '../../vendors/vjsc/vjsc-1.1.1'
import { SchnorrProof } from './SchnorrProof'

var crypto2 = require('crypto')

export class SchnorrProofHelios extends SchnorrProof {
  constructor(hom: arithm.ExpHom) {
      super(hom)
  }
  
  challenge(first: eio.ByteTree, second: crypto.HashFunction): arithm.PRingElement {   
      const commitmentsBt = <eio.ByteTree> first.value[2]
      const commitments = <Array<eio.ByteTree>> commitmentsBt.value
      
      const cStrings: Array<String> = commitments.map( (value: eio.ByteTree) => {
          if(value.value[0] instanceof eio.ByteTree) {
          
              const pair: Array<eio.ByteTree> = <Array<eio.ByteTree>> value.value

              const a = BigInt("0x" + util.byteArrayToHex(<Uint8Array> pair[0].value) ).toString()
              
              const b = BigInt("0x" + util.byteArrayToHex(<Uint8Array> pair[1].value) ).toString()
              
              return a + "," + b
          }
          else {
              return BigInt("0x" + util.byteArrayToHex(<Uint8Array> value.value) ).toString()
          }
      })
  
      const all = cStrings.join(",")
      const digest = this.sha1(all)
      const digestBytes = util.hexToByteArray(digest)
      
      const challenge = this.homomorphism.domain.getPField().toElement(digestBytes)
      
      return challenge
  }

  private sha1(bytes: string): string {
    return crypto2.createHash('sha1').update(bytes).digest('hex')
  }
}
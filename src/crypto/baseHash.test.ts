import { createBaseHash, createExtendedBaseHash } from './baseHash'
import { util } from '../../vendors/vjsc/vjsc-1.1.1'

// base hash is still not being correctly calculated, it thus always returns
// returns an empty value
test('createBaseHash', () => {
  expect(createBaseHash()).toStrictEqual(util.hexToByteArray('0'))
})

// extended base hash is still not being correctly calculated, it thus always
// returns an empty value
test('createExtendedBaseHash', () => {
  expect(createExtendedBaseHash()).toStrictEqual(util.hexToByteArray('0'))
})

import * as utils from './utils'
import { arithm, eio } from '../../vendors/vjsc/vjsc-1.1.1'

test('isNull', () => {
  expect(utils.isNull(null)).toBe(true)
  expect(utils.isNull('a')).toBe(false)
  expect(utils.isNull(undefined)).toBe(false)
  expect(utils.isNull([1, 2, 3])).toBe(false)
})

test('isError', () => {
  expect(utils.isError(new Error())).toBe(true)
  expect(utils.isError(new Error('whatever'))).toBe(true)
  expect(utils.isError('a')).toBe(false)
  expect(utils.isError(undefined)).toBe(false)
  expect(utils.isError([1, 2, 3])).toBe(false)
})

test('flatten2D', () => {
  expect(utils.flatten2D([[1], [2, 3]])).toStrictEqual([1, 2, 3])
  expect(utils.flatten2D([[], []])).toStrictEqual([])
  expect(utils.flatten2D([])).toStrictEqual([])
})

test('firstError', () => {
  const error1 = new Error('whatever')
  const error2 = new Error('possible')
  expect(utils.firstError([])).toStrictEqual(new Error())
  expect(utils.firstError([error2])).toStrictEqual(error2)
  expect(utils.firstError([error1, error2])).toStrictEqual(error1)
})

test('strDecToHex', () => {
  expect(utils.strDecToHex('1')).toBe('1')
  expect(utils.strDecToHex('15')).toBe('f')
  expect(utils.strDecToHex('256')).toBe('100')
})

test('strDecToByteArray', () => {
  expect(utils.strDecToByteArray('1')).toStrictEqual([1])
  expect(utils.strDecToByteArray('15')).toStrictEqual([15])
  expect(utils.strDecToByteArray('256')).toStrictEqual([1, 0])
})

test('strDecToByteTree', () => {
  expect(
    (utils.strDecToByteTree('1') as eio.ByteTree).toByteArrayRaw()
  ).toStrictEqual([1])
  expect(
    (utils.strDecToByteTree('15') as eio.ByteTree).toByteArrayRaw()
  ).toStrictEqual([15])
  expect(
    (utils.strDecToByteTree('256') as eio.ByteTree).toByteArrayRaw()
  ).toStrictEqual([1, 0])
})

test('strDecToPRingElement', () => {
  const groupName = 'modp2048'
  const params: string[] = arithm.ModPGroup.getParams(groupName)
  const group: arithm.ModPGroup = arithm.ModPGroup.getPGroup(groupName)

  expect(utils.strDecToPRingElement('12', group.pRing)).toStrictEqual(
    group.pRing.toElement(utils.strDecToByteTree('12') as eio.ByteTree)
  )
})

test('removeSpaces', () => {
  expect(utils.removeSpaces('')).toBe('')
  expect(utils.removeSpaces(' a be  c \tedario  \r')).toBe('abecedario\r')
})

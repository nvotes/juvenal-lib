import { util, eio, arithm } from '../../vendors/vjsc/vjsc-1.1.1'

/**
 * Type predicate that returns whether the object is null
 * and narrows the type to either as null or the alternative
 * type in a nested code block.
 *
 * @param obj obj we want to differentiate the type of
 */
export function isNull(obj: unknown | null): obj is null {
  return obj === null
}

/**
 * Type predicate that returns whether the object is an error
 * and narrows the type to either an error or the alternative
 * type in a nested code block.
 *
 * @param obj obj we want to differentiate the type of
 */
export function isError(obj: unknown | Error): obj is Error {
  return obj instanceof Error
}

/**
 * Flattens a 2D array into a 1D array. We need this
 * custom function as flatMap is not supported yet in ES027
 *
 * @param obj 2D array we want to flatten into 1D
 */
export function flatten2D<T>(array: T[][]): T[] {
  return ([] as T[]).concat(...array)
}

/**
 * Returns the first error of the list or an empty error, but always
 * an error. This is useful if we have a lot of errors, to get the
 * first of them.
 *
 * @param list list of errors
 */
export function firstError(list: (unknown | Error)[]): Error {
  const emptyError = new Error()
  for (const error of list) {
    if (isError(error)) {
      return error
    }
  }
  return emptyError
}

/**
 * Receives a string of a number in decimal base and returns it in
 * hexadecimal base, also as a string.
 *
 * @param decLiStr A decimal large integer number either as a string
 *                   or as a native typescript number.
 */
export function strDecToHex(decLiStr: string | number): string {
  return BigInt(decLiStr).toString(16)
}

/**
 * Receives a string of a number in decimal base and returns it as
 * a byte array.
 * @param decLiStr A decimal large integer number either as a string
 *                   or as a native typescript number.
 */
export function strDecToByteArray(decLiStr: string | number): Uint8Array {
  return util.hexToByteArray(BigInt(decLiStr).toString(16))
}

/**
 * Converts a number as a string into a byte tree of the correct size.
 *
 * @param decLiStr A decimal large integer number either as a string
 *                   or as a native typescript number
 */
export function strDecToByteTree(
  decLiStr: string | number
): eio.ByteTree | Error {
  const hex = strDecToHex(decLiStr)

  return eio.ByteTree.asByteTree(util.hexToByteArray(hex))
}

/**
 * Converts a number as a string into a ModPGroupElement.
 *
 * @param decLiStr A decimal large integer number either as a string
 *                   or as a native typescript number.
 * @param modPGroup The multiplicative modular group to be used.
 */
export function strDecToModPGroupElement(
  decLiStr: string | number,
  modPGroup: arithm.ModPGroup
): arithm.ModPGroupElement | Error {
  // First convert it to byte tree, dealing with errors if any
  const byteTree = strDecToByteTree(decLiStr)

  if (isError(byteTree)) {
    const error: Error = byteTree
    return error
  }

  // Then convert it to a group element, dealing with errors if any
  let element: arithm.ModPGroupElement
  try {
    element = modPGroup.toElementAlt(byteTree)
  } catch (error) {
    return error
  }

  return element
}

/**
 * Converts a number as a string into a PRingElement.
 *
 * @param decLiStr A decimal large integer number either as a string
 *                   or as a native typescript number.
 * @param ring The ring to be used.
 */
export function strDecToPRingElement(
  decLiStr: string | number,
  ring: arithm.PRing
): arithm.PRingElement | Error {
  // First convert it to byte tree, dealing with errors if any
  const byteTree = strDecToByteTree(decLiStr)

  if (isError(byteTree)) {
    const error: Error = byteTree
    return error
  }

  // Then convert it to a group element, dealing with errors if any
  let element: arithm.PRingElement
  try {
    element = ring.toElement(byteTree)
  } catch (error) {
    return error
  }

  return element
}

/**
 * Returns the string without any spaces
 * @param str input string
 */
export function removeSpaces(str: string): string {
  return str.replace(/[ \t\n]/g, '')
}

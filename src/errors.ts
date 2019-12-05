export class UnrecoverableError extends Error {}
export class RecoverableError extends Error {}

/**
 * Shows an error in console and exit the process with error.
 *
 * @param error error to be shown
 */
export function exitError(error: Error) {
  console.error(error.name + ' ' + error.message)
  process.exit(1)
}

/**
 * Shows an error in console and exit the process with error.
 *
 * @param error error to be shown
 */
export function exitErrorString(errorString: string) {
  console.error('ERROR: ' + errorString)
  process.exit(1)
}

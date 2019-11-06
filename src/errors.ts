export class UnrecoverableError extends Error {};
export class RecoverableError extends Error {};

/**
 * Shows an error in console and exit the process with error.
 * 
 * @param error error to be shown
 */
export function exit_error(error: Error) {
    console.error(error.name + " " + error.message);
    process.exit(1);
}

/**
 * Shows an error in console and exit the process with error.
 * 
 * @param error error to be shown
 */
export function exit_error_string(error_string: String) {
    console.error("ERROR: " + error_string);
    process.exit(1);
}

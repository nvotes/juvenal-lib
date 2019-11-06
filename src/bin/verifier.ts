/**
 * Verifier command-line binary.
 * 
 * Usage: `node verify.js <path-to-election-record-file>`
 */
import * as fs from 'fs';
import * as path from 'path';
import { exit_error_string, exit_error} from '../errors';
import { verify_election_record } from '../verify';
import { CLIRecorder } from '../CLIRecorder';

main(process.argv);

/**
 * Main function of the verifier command-line binary.
 * 
 * @param argv Parameters received by the binary. It's asumed the first one
 *             is node, the second is the path to this binary, and the third 
 *             parameter should be the path to the election record file.
 */
function main(argv: string[]) {
  if (argv.length < 3) {
    exit_error_string(
      "Please specify path to election record file.\n\n" +
      "Usage: node verify.js <path-to-election-record-file>"
    );
  }
  let election_record_path = argv[2];

  // Try to read the election record file
  fs.readFile(election_record_path, 'utf8', (err, data) => {
    // couldn't read the file for some reason
    if (err) {
      exit_error_string(
        "Couldn't read election record file '" + election_record_path + "'"
      );
    }

    let recorder = new CLIRecorder();
    verify_election_record(data, exit_error, recorder);
  })
}

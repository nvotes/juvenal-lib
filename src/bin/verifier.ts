/**
 * Verifier command-line binary.
 * 
 * Usage: `node verify.js <path-to-election-record-file>`
 */
import * as fs from 'fs';
import * as path from 'path';
import { exitErrorString, exitError} from '../errors';
import { verifyElectionRecord } from '../verify';
import { CLIRecorder } from '../recorders/CLIRecorder';

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
    exitErrorString(
      "Please specify path to election record file.\n\n" +
      "Usage: node verify.js <path-to-election-record-file>"
    );
  }
  const electionRecordPath = argv[2];

  // Try to read the election record file
  fs.readFile(electionRecordPath, 'utf8', (error, data) => {
    // couldn't read the file for some reason
    if (error) {
      exitErrorString(
        "Couldn't read election record file '" + electionRecordPath + "'"
      );
    }

    const recorder = new CLIRecorder();
    verifyElectionRecord(data, exitError, recorder);
  })
}

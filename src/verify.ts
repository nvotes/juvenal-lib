/**
 * Main functions that are used to execute the verification of an election
 * record. 
 * 
 * All functions in here should be portable, usable both in a web frontend
 * or in a node backend.
 */
import { ElectionRecord } from '../vendors/electionguard-schema-0.85/@types/election_record';
import { VRecorder } from './recorders/VRecorder';
import { VElectionRecord } from './records/VElectionRecord';
import { isError } from './crypto/utils';

/**
 * Verifies an election record.
 * 
 * @param electionRecordString Election record as a string
 * @param errorHandler What to call if there's any unrecoverable error
 * @param recorder Verification recorder to use, for example the CLIRecorder
 */
export function verifyElectionRecord(
    electionRecordString: string, 
    errorHandler: (err: Error) => void,
    recorder: VRecorder
): void {
    const record = getElectionRecord(electionRecordString);
    if (isError(record)) {
        const error = record;
        errorHandler(error);
    } else {
        const vElectionRecord = new VElectionRecord(record);
        vElectionRecord.verify(recorder);
    }
}

/**
 * Reads a string containing an election record and returns it as an election
 * record, without validating its json schema.
 * 
 * @param recordString Election Record as a string
 */
function getElectionRecord(recordString: string):
    ElectionRecord | Error
{
    // Get this json as an election record
    try {
        let record: ElectionRecord = JSON.parse(recordString);
        return record;
    } catch(error) {
        return new Error("Could not load election record as json");
    }
};

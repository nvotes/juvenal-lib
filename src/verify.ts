/**
 * Main functions that are used to execute the verification of an election
 * record. 
 * 
 * All functions in here should be portable, usable both in a web frontend
 * or in a node backend.
 */
import { ElectionRecord } from '../vendors/electionguard-schema-0.85/@types/election_record';
import { VRecorder } from './VRecorder';
import { VElectionRecord } from './records/VElectionRecord';

/**
 * Verifies an election record.
 * 
 * @param election_record_string Election record as a string
 * @param error_handler What to call if there's any unrecoverable error
 * @param recorder Verification recorder to use, for example the CLIRecorder
 */
export function verify_election_record(
    election_record_string: string, 
    error_handler: (err: Error) => void,
    recorder: VRecorder
): void {
    const [record_error, record] = get_election_record(election_record_string);
    if (record_error) {
        error_handler(record_error);
    }
    const velection_record = new VElectionRecord(record as ElectionRecord);
    velection_record.verify(recorder);
}

/**
 * Reads a string containing an election record and returns it as an election
 * record, without validating its json schema.
 * 
 * @param record_string Election Record as a string
 */
function get_election_record(record_string: string):
    [Error | null, ElectionRecord | null] 
{
    // Get this json as an election record
    try {
        let record: ElectionRecord = JSON.parse(record_string);
        return [null, record];
    } catch(e) {
        return [new Error("Could not load election record as json"), null];
    }
};

import { VRecorder } from '../VRecorder';

/**
 * Interface for election records that allows operations such as
 * verification and also generation of new records.
 */
export interface VRecord {
    /**
     * Verify the record.
     * 
     * @param recorder Recorder to record the verification
     */
    verify(recorder: VRecorder): void;

    /**
     * Returns the context of this record, useful for showing the
     * context of a verification in the record. 
     * 
     * The context is just a list of strings, showing the tree path
     * to the record.
     */
    context(): string[]
}
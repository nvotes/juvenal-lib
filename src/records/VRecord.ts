import { VRecorder } from '../VRecorder';

/**
 * Interface for election records that allows operations such as
 * verification and also generation of new records.
 */
export interface VRecord {
    verify(recorder: VRecorder): void;
}
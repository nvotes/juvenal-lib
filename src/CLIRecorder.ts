/**
 * Implements the command line recorder, which prints output to
 * stdout and records if there was any failure.
 */
import { VRecorder } from './VRecorder';

/**
 * Command line Verification recorder, which prints output to
 * stdout and records if there was any failure.
 */
export class CLIRecorder implements VRecorder {
    _has_failures: boolean;

    constructor() { 
        this._has_failures = false; 
    }
    
    record(
        status: boolean,
        context: string[],
        name: string,
        title: string
    ): void {
        this._has_failures = this._has_failures || !status;

        let stat2str = (status: boolean): string => (status) ? "OK:  " : "FAIL:";
        const prefix = context.join(", ");
        console.log(stat2str(status) + " " + prefix + " | " + name + ": " + title);
    }

    has_failures(): boolean {
        return this._has_failures;
    }
}
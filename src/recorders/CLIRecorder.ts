/**
 * Implements the command line recorder, which prints output to
 * stdout and records if there was any failure.
 */
import { VRecorder } from './VRecorder'

/**
 * Command line Verification recorder, which prints output to
 * stdout and records if there was any failure.
 */
export class CLIRecorder implements VRecorder {
  hasFailures: boolean

  constructor() {
    this.hasFailures = false
  }

  record(
    status: boolean,
    context: string[],
    name: string,
    title: string
  ): void {
    this.hasFailures = this.hasFailures || !status

    const stat2str = (status: boolean): string => (status ? 'OK:  ' : 'FAIL:')
    const prefix = context.join(', ')
    console.log(stat2str(status) + ' ' + prefix + ' | ' + name + ': ' + title)
  }
}

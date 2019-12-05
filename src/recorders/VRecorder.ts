/**
 * Records a verification. A CLI verifier might log this in the
 * stdout, while a web verifier could show it in HTML.
 */
export interface VRecorder {
  /**
   * Returns wether there was any verification that failed
   */
  readonly hasFailures: boolean

  /**
   * Record a verification.
   *
   * Note that multiple calls with the same verification id could happen, but
   * if any of them is a failure they should be end up recorded internall
   * as a failure for that VerificationId.
   *
   * @param status Status of the verification
   * @param context List of contexts of the verification, a context could be
   *                "contest 1"
   * @param name Camel case name of the verification
   * @param title Title of the verification
   */
  record(status: boolean, context: string[], name: string, title: string): void
}

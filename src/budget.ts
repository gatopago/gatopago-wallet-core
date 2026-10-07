/**
 * External requests one scheduled run may still make. Workers Free allows 50 subrequests per
 * invocation (`SUBREQUESTS_PER_RUN`); a job that runs out stops and resumes on the next run.
 */
export class Budget {
  constructor(private left: number) {}

  /** Reserves `count` requests; false when they no longer fit. */
  take(count = 1): boolean {
    if (this.left < count) return false;
    this.left -= count;
    return true;
  }
}

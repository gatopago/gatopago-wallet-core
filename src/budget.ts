/**
 * External requests one scheduled run may still make. Workers Free allows 50 subrequests per
 * invocation (`SUBREQUESTS_PER_RUN`); a job that runs out stops and resumes on the next run.
 */
export class Budget {
  constructor(
    private left: number,
    private readonly parent?: Budget,
  ) {}

  /** Reserves `count` requests; false when they no longer fit. */
  take(count = 1): boolean {
    if (this.left < count || (this.parent && !this.parent.take(count))) return false;
    this.left -= count;
    return true;
  }

  /**
   * An even part of what is left, for one of `parts` jobs that take turns: one far behind or
   * failing does not take the others' turn, and what it leaves unused stays here for the next.
   */
  share(parts: number): Budget {
    return new Budget(Math.floor(this.left / parts), this);
  }
}

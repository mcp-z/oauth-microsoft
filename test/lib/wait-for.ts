/** Repeat `check` until it holds; the run's kill timer is the only bound. */
export async function waitFor(check: () => boolean): Promise<void> {
  while (!check()) {
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
}

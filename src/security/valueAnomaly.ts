export function scoreValueJump(delta: number, baseline = false): number {
  if (baseline || !Number.isFinite(delta)) return 0;
  const absoluteJump = Math.abs(delta);
  if (absoluteJump >= 10_000) return 100;
  if (absoluteJump >= 1_000) return 80;
  if (absoluteJump >= 500) return 50;
  return 0;
}

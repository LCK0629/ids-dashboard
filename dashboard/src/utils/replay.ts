import type { ReplaySpeed } from '../types/feedback';

export function replayIntervalMs(speed: ReplaySpeed): number {
  if (speed === 5) {
    return 200;
  }
  if (speed === 2) {
    return 500;
  }
  return 1000;
}

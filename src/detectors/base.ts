/** Base detector interface. */

import { DetectedEntity } from "../types.js";

export interface BaseDetector {
  readonly name: string;
  detect(text: string): DetectedEntity[];
  /** Optional reset for stateful detectors. */
  reset?(): void;
}

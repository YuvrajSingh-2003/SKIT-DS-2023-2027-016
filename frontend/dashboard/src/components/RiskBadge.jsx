/**
 * RiskBadge
 *
 * Displays a colour-coded pill for the scan risk level returned by the backend.
 * Valid values: "SAFE" | "MEDIUM" | "HIGH" | "LOW" | "UNKNOWN" (wording in riskLabels.js)
 *
 * The badge maps directly to CSS classes defined in index.css.
 */

import { riskLabel } from "../riskLabels.js";

/**
 * @param {{ level: string }} props
 */
export default function RiskBadge({ level }) {
  const { label, cls, icon } = riskLabel(level);

  return (
    <span className={`badge ${cls}`} aria-label={`Risk level: ${label}`}>
      <span aria-hidden="true">{icon}</span>
      {label}
    </span>
  );
}

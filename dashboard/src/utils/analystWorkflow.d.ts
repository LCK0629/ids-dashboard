import type { FeedbackAdjustedAlert } from '../types/alerts';
import type { AnalystAlertV1 } from '../types/dashboardData';

export interface WorkflowPresentation {
  key: string;
  label: string;
  tone: 'positive' | 'warning' | 'neutral' | 'muted';
}

export function getHistoricalAdjustmentPresentation(
  adaptation: AnalystAlertV1['adaptation'],
): WorkflowPresentation;
export function getReviewWorkflowPresentation(
  alert: FeedbackAdjustedAlert,
  analystAlert?: AnalystAlertV1,
): WorkflowPresentation;

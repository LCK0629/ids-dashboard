import type { FeedbackEvaluationSummary, FlowAlertCounts, FusionEvaluationSummary } from '../types/alerts';
import { formatPercent } from '../utils/alertFilters';

export type DashboardView = 'operations' | 'investigations' | 'feedback' | 'reports';

interface SidebarProps {
  activeView: DashboardView;
  onViewChange: (view: DashboardView) => void;
  feedbackSummary: FeedbackEvaluationSummary;
  flowAlertCounts: FlowAlertCounts;
  fusionSummary: FusionEvaluationSummary;
}

const navItems: Array<{ view: DashboardView; title: string; subtitle: string }> = [
  { view: 'operations', title: 'Operations', subtitle: 'Active alert triage' },
  { view: 'investigations', title: 'Investigations', subtitle: 'Case timeline' },
  { view: 'feedback', title: 'Feedback Model', subtitle: 'Adaptive scoring' },
  { view: 'reports', title: 'Reports', subtitle: 'Evaluation summary' },
];

export function Sidebar({
  activeView,
  onViewChange,
  feedbackSummary,
  flowAlertCounts,
  fusionSummary,
}: SidebarProps) {
  return (
    <aside className="sidebar" aria-label="Security workspace navigation">
      <div className="brand">
        <div className="brand-mark">ID</div>
        <div>
          <strong>IDS Console</strong>
          <span>Human-in-the-loop triage</span>
        </div>
      </div>

      <nav className="nav-list">
        {navItems.map((item) => (
          <button
            className={activeView === item.view ? 'nav-item active' : 'nav-item'}
            key={item.view}
            onClick={() => onViewChange(item.view)}
            type="button"
          >
            <strong>{item.title}</strong>
            <span>{item.subtitle}</span>
          </button>
        ))}
      </nav>

      <div className="model-card flow-alert-summary">
        <span className="label">Flow vs Alert Summary</span>
        <p>Not every flow is an alert.</p>
        <div className="sidebar-count-group">
          <strong>Flow Records</strong>
          <span><b>{flowAlertCounts.totalProcessedFlows}</b> Processed Flows</span>
          <span><b>{flowAlertCounts.allDetectionRecords}</b> Detection Records</span>
        </div>
        <div className="sidebar-count-group">
          <strong>Alert Queue</strong>
          <span><b>{flowAlertCounts.activeAlerts}</b> Active Alerts</span>
          <span><b>{flowAlertCounts.reviewRequiredAlerts}</b> Requires Review</span>
          <span><b>{flowAlertCounts.highRiskRecords}</b> High Risk</span>
        </div>
        <div className="sidebar-count-group">
          <strong>Suppressed / Audit</strong>
          <span><b>{flowAlertCounts.suppressedOrResolvedRecords}</b> Suppressed / Resolved</span>
          <span><b>{flowAlertCounts.lowRiskRecords}</b> Low Risk Records</span>
        </div>
        <p>Flows are scored first. Only review-worthy records become active alerts.</p>
      </div>

      <div className="model-card">
        <span className="label">Pipeline Status</span>
        <strong>{fusionSummary.idAlignmentSummary?.alignmentStatus || 'N/A'}</strong>
        <p>{formatPercent(fusionSummary.idAlignmentSummary?.overlapRateAgainstStage2)} Stage 4 ID overlap</p>
      </div>

      <div className="model-card">
        <span className="label">Feedback Impact</span>
        <strong>{feedbackSummary.alertsAdjusted ?? 'N/A'}</strong>
        <p>Adjusted detection records from simulated analyst feedback and exception memory</p>
      </div>
    </aside>
  );
}

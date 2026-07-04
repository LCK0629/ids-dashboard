import type { FeedbackEvaluationSummary, FusionEvaluationSummary } from '../types/alerts';
import { formatPercent } from '../utils/alertFilters';

export type DashboardView = 'operations' | 'investigations' | 'feedback' | 'reports';

interface SidebarProps {
  activeView: DashboardView;
  onViewChange: (view: DashboardView) => void;
  feedbackSummary: FeedbackEvaluationSummary;
  fusionSummary: FusionEvaluationSummary;
}

const navItems: Array<{ view: DashboardView; title: string; subtitle: string }> = [
  { view: 'operations', title: 'Operations', subtitle: 'Active alert triage' },
  { view: 'investigations', title: 'Investigations', subtitle: 'Case timeline' },
  { view: 'feedback', title: 'Feedback Model', subtitle: 'Adaptive scoring' },
  { view: 'reports', title: 'Reports', subtitle: 'Evaluation summary' },
];

export function Sidebar({ activeView, onViewChange, feedbackSummary, fusionSummary }: SidebarProps) {
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

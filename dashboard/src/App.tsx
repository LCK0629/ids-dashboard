import { useMemo, useState } from 'react';
import feedbackAdjustedAlerts from './data/feedback-adjusted-alerts.sample.json';
import feedbackEvaluationSummary from './data/feedback-evaluation-summary.json';
import fusionEvaluationSummary from './data/fusion-evaluation-summary.json';
import { AlertDetailPanel } from './components/AlertDetailPanel';
import { AlertQueue } from './components/AlertQueue';
import { FilterBar } from './components/FilterBar';
import { KpiCards } from './components/KpiCards';
import type {
  FeedbackAdjustedAlert,
  FeedbackEvaluationSummary,
  FilterKey,
  FusionEvaluationSummary,
} from './types/alerts';
import { filterAlerts, sortAlerts } from './utils/alertFilters';

const alerts = feedbackAdjustedAlerts as FeedbackAdjustedAlert[];
const feedbackSummary = feedbackEvaluationSummary as FeedbackEvaluationSummary;
const fusionSummary = fusionEvaluationSummary as FusionEvaluationSummary;

export default function App() {
  const [activeFilter, setActiveFilter] = useState<FilterKey>('all');
  const sortedAlerts = useMemo(() => sortAlerts(alerts), []);
  const filteredAlerts = useMemo(
    () => filterAlerts(sortedAlerts, activeFilter),
    [activeFilter, sortedAlerts]
  );
  const [selectedAlertId, setSelectedAlertId] = useState<string | undefined>(sortedAlerts[0]?.id);
  const selectedAlert = filteredAlerts.find((alert) => alert.id === selectedAlertId)
    || filteredAlerts[0]
    || sortedAlerts[0];

  return (
    <main className="dashboard-shell">
      <header className="hero">
        <div>
          <span className="stage-pill">Stage 6 Dashboard Integration</span>
          <h1>Human-in-the-Loop IDS Dashboard</h1>
          <p>Hybrid signature, ML, fusion, and analyst-feedback alert prioritisation</p>
        </div>
        <div className="header-meta">
          <span>Static JSON integration</span>
          <strong>{fusionSummary.idAlignmentSummary?.alignmentStatus || 'N/A'}</strong>
        </div>
      </header>

      <KpiCards feedbackSummary={feedbackSummary} fusionSummary={fusionSummary} />

      <FilterBar
        activeFilter={activeFilter}
        onFilterChange={(filter) => {
          setActiveFilter(filter);
          setSelectedAlertId(undefined);
        }}
        totalCount={sortedAlerts.length}
        visibleCount={filteredAlerts.length}
      />

      <section className="workspace">
        <AlertQueue
          alerts={filteredAlerts}
          selectedAlertId={selectedAlert?.id}
          onSelectAlert={(alert) => setSelectedAlertId(alert.id)}
        />
        <AlertDetailPanel alert={selectedAlert} />
      </section>
    </main>
  );
}

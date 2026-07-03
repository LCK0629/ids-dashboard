import { useMemo, useState } from 'react';
import feedbackAdjustedAlerts from './data/feedback-adjusted-alerts.sample.json';
import feedbackEvaluationSummary from './data/feedback-evaluation-summary.json';
import fusionEvaluationSummary from './data/fusion-evaluation-summary.json';
import { AlertDetailPanel } from './components/AlertDetailPanel';
import { AlertQueue } from './components/AlertQueue';
import { FeedbackSummaryPanel } from './components/FeedbackSummaryPanel';
import { FilterBar } from './components/FilterBar';
import { Header } from './components/Header';
import { InvestigationsPanel } from './components/InvestigationsPanel';
import { KpiCards } from './components/KpiCards';
import { OperationalOverview } from './components/OperationalOverview';
import { ReportsPanel } from './components/ReportsPanel';
import { Sidebar, type DashboardView } from './components/Sidebar';
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

const viewLabels: Record<DashboardView, string> = {
  operations: 'Operations',
  investigations: 'Investigations',
  feedback: 'Feedback Model',
  reports: 'Reports',
};

export default function App() {
  const [activeFilter, setActiveFilter] = useState<FilterKey>('all');
  const [activeView, setActiveView] = useState<DashboardView>('operations');
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
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        feedbackSummary={feedbackSummary}
        fusionSummary={fusionSummary}
        onViewChange={setActiveView}
      />

      <main className="dashboard">
        <Header activeLabel={viewLabels[activeView]} />
        <KpiCards feedbackSummary={feedbackSummary} fusionSummary={fusionSummary} />

        {activeView === 'operations' && (
          <>
            <OperationalOverview alerts={sortedAlerts} feedbackSummary={feedbackSummary} />
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
              <div className="main-column">
                <AlertQueue
                  alerts={filteredAlerts}
                  selectedAlertId={selectedAlert?.id}
                  onSelectAlert={(alert) => setSelectedAlertId(alert.id)}
                />
              </div>
              <AlertDetailPanel alert={selectedAlert} />
            </section>
          </>
        )}

        {activeView === 'investigations' && <InvestigationsPanel alert={selectedAlert} />}
        {activeView === 'feedback' && <FeedbackSummaryPanel summary={feedbackSummary} />}
        {activeView === 'reports' && (
          <ReportsPanel feedbackSummary={feedbackSummary} fusionSummary={fusionSummary} />
        )}
      </main>
    </div>
  );
}

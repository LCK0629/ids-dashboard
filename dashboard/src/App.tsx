import { useEffect, useMemo, useState } from 'react';
import analystAlertsData from './data/analyst-alerts.v1.json';
import evaluatorSummaryData from './data/evaluator-summary.v1.json';
import { AlertDetailPanel } from './components/AlertDetailPanel';
import { AlertQueue } from './components/AlertQueue';
import { FeedbackSummaryPanel } from './components/FeedbackSummaryPanel';
import { FilterBar } from './components/FilterBar';
import { Header } from './components/Header';
import { InvestigationsPanel } from './components/InvestigationsPanel';
import { KpiCards } from './components/KpiCards';
import { LatestActivityPanel } from './components/LatestActivityPanel';
import { OperationalOverview } from './components/OperationalOverview';
import { ReportsPanel } from './components/ReportsPanel';
import { ReplayControls } from './components/ReplayControls';
import { Sidebar, type DashboardView } from './components/Sidebar';
import type {
  FeedbackAdjustedAlert,
  FeedbackEvaluationSummary,
  AttackTypeFilter,
  FilterKey,
  FusionEvaluationSummary,
} from './types/alerts';
import type { AnalystFeedbackAction, LocalFeedbackMap, ReplaySpeed } from './types/feedback';
import type { AnalystArtifactV1, EvaluatorSummaryArtifactV1 } from './types/dashboardData';
import { validateAnalystArtifact, validateEvaluatorArtifact } from './data-contract/analystDashboardContract.js';
import { adaptAnalystAlertsForLegacyComponents } from './utils/dashboardAdapter';
import {
  applySessionPreviewOverrides,
  calculateSessionKpis,
  createSessionPreviewOverride,
} from './utils/feedback';
import {
  attackTypeOptions,
  filterAlerts,
  filterAlertsByAttackType,
  getFlowAlertCounts,
  sortAlerts,
} from './utils/alertFilters';
import { replayIntervalMs } from './utils/replay';

const analystArtifactValidation = validateAnalystArtifact(analystAlertsData);
const analystArtifact = analystArtifactValidation.valid
  ? analystAlertsData as AnalystArtifactV1
  : null;
const evaluatorArtifactValidation = validateEvaluatorArtifact(evaluatorSummaryData);
const evaluatorArtifact = evaluatorArtifactValidation.valid
  ? evaluatorSummaryData as EvaluatorSummaryArtifactV1
  : null;
const alerts = analystArtifact
  ? adaptAnalystAlertsForLegacyComponents(analystArtifact.alerts)
  : [];
const feedbackSummary = (evaluatorArtifact?.feedbackSummary || {}) as unknown as FeedbackEvaluationSummary;
const fusionSummary = (evaluatorArtifact?.fusionSummary || {}) as unknown as FusionEvaluationSummary;

const viewLabels: Record<DashboardView, string> = {
  operations: 'Operations',
  investigations: 'Investigations',
  feedback: 'Feedback Model',
  reports: 'Reports',
};

const filterTitles: Record<FilterKey, string> = {
  'active-alerts': 'Active Alert Queue',
  'all-records': 'All Detection Records',
  'requires-review': 'Review-Required Alerts',
  'feedback-applied': 'Feedback-Adjusted Records',
  'high-risk': 'High Risk Records',
  'medium-risk': 'Medium Risk Records',
  'low-risk': 'Low Risk Records',
  'suppressed-resolved': 'Suppressed / Resolved Records',
  'signature-hit': 'Signature Hit Records',
  'signature-ml-disagree': 'Signature / ML Disagreement Records',
  'guardrail-applied': 'Score Guardrail Applied Records',
  'exception-trust-gate': 'Exception Trust Gate Rejected Records',
};

export default function App() {
  const [activeFilter, setActiveFilter] = useState<FilterKey>('active-alerts');
  const [activeAttackType, setActiveAttackType] = useState<AttackTypeFilter>('all');
  const [activeView, setActiveView] = useState<DashboardView>('operations');
  const [isReplayMode, setIsReplayMode] = useState(false);
  const [isReplayRunning, setIsReplayRunning] = useState(false);
  const [replayIndex, setReplayIndex] = useState(alerts.length);
  const [replaySpeed, setReplaySpeed] = useState<ReplaySpeed>(1);
  const [localFeedbackMap, setLocalFeedbackMap] = useState<LocalFeedbackMap>({});

  const locallyAdjustedAlerts = useMemo(
    () => applySessionPreviewOverrides(alerts, localFeedbackMap),
    [localFeedbackMap]
  );
  const replayVisibleAlerts = useMemo(
    () => (isReplayMode ? locallyAdjustedAlerts.slice(0, replayIndex) : locallyAdjustedAlerts),
    [isReplayMode, locallyAdjustedAlerts, replayIndex]
  );
  const flowAlertCounts = useMemo(
    () => getFlowAlertCounts(locallyAdjustedAlerts),
    [locallyAdjustedAlerts]
  );
  const sortedAlerts = useMemo(() => sortAlerts(replayVisibleAlerts), [replayVisibleAlerts]);
  const attackTypes = useMemo(() => attackTypeOptions(replayVisibleAlerts), [replayVisibleAlerts]);
  const filteredAlerts = useMemo(() => {
    const stageFilteredAlerts = filterAlerts(sortedAlerts, activeFilter);
    return filterAlertsByAttackType(stageFilteredAlerts, activeAttackType);
  }, [activeAttackType, activeFilter, sortedAlerts]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | undefined>(sortedAlerts[0]?.id);
  const selectedAlert = filteredAlerts.find((alert) => alert.id === selectedAlertId)
    || filteredAlerts[0]
    || sortedAlerts[0];
  const sessionKpis = useMemo(
    () => calculateSessionKpis(filteredAlerts, sortedAlerts, localFeedbackMap, isReplayMode ? replayIndex : alerts.length, alerts.length),
    [filteredAlerts, isReplayMode, localFeedbackMap, replayIndex, sortedAlerts]
  );

  useEffect(() => {
    if (!isReplayMode || !isReplayRunning) {
      return undefined;
    }

    const interval = window.setInterval(() => {
      setReplayIndex((currentIndex) => {
        const nextIndex = Math.min(alerts.length, currentIndex + 1);
        if (nextIndex >= alerts.length) {
          setIsReplayRunning(false);
        }
        return nextIndex;
      });
    }, replayIntervalMs(replaySpeed));

    return () => window.clearInterval(interval);
  }, [isReplayMode, isReplayRunning, replaySpeed]);

  useEffect(() => {
    if (!selectedAlertId || !sortedAlerts.some((alert) => alert.id === selectedAlertId)) {
      setSelectedAlertId(filteredAlerts[0]?.id || sortedAlerts[0]?.id);
    }
  }, [filteredAlerts, selectedAlertId, sortedAlerts]);

  useEffect(() => {
    if (activeAttackType !== 'all' && !attackTypes.includes(activeAttackType)) {
      setActiveAttackType('all');
    }
  }, [activeAttackType, attackTypes]);

  function applyFeedback(alert: FeedbackAdjustedAlert, action: AnalystFeedbackAction) {
    setLocalFeedbackMap((currentMap) => ({
      ...currentMap,
      [alert.id]: createSessionPreviewOverride(alert, action),
    }));
    setSelectedAlertId(alert.id);
  }

  function resetFeedback(alert: FeedbackAdjustedAlert) {
    setLocalFeedbackMap((currentMap) => {
      const nextMap = { ...currentMap };
      delete nextMap[alert.id];
      return nextMap;
    });
    setSelectedAlertId(alert.id);
  }

  function resetReplay() {
    setReplayIndex(0);
    setIsReplayMode(true);
    setIsReplayRunning(false);
    setLocalFeedbackMap({});
    setSelectedAlertId(undefined);
  }

  if (!analystArtifact || !evaluatorArtifact) {
    const artifactErrors = [
      ...analystArtifactValidation.errors.map((error) => `Analyst artifact: ${error}`),
      ...evaluatorArtifactValidation.errors.map((error) => `Evaluator artifact: ${error}`),
    ];
    return (
      <main className="dashboard artifact-error" role="alert">
        <section className="panel full-panel">
          <div className="panel-header">
            <h1>Dashboard data unavailable</h1>
          </div>
          <p>A dashboard data artifact failed schema validation. No alert records or evaluator metrics were loaded.</p>
          <ul>
            {artifactErrors.map((error) => <li key={error}>{error}</li>)}
          </ul>
        </section>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        feedbackSummary={feedbackSummary}
        flowAlertCounts={flowAlertCounts}
        fusionSummary={fusionSummary}
        onViewChange={setActiveView}
      />

      <main className="dashboard">
        <Header activeLabel={viewLabels[activeView]} />
        {activeView === 'operations' && (
          <>
            <ReplayControls
              isReplayMode={isReplayMode}
              isReplayRunning={isReplayRunning}
              onPause={() => setIsReplayRunning(false)}
              onReset={resetReplay}
              onResume={() => {
                setIsReplayMode(true);
                setIsReplayRunning(true);
              }}
              onShowAll={() => {
                setReplayIndex(alerts.length);
                setIsReplayRunning(false);
              }}
              onSpeedChange={setReplaySpeed}
              onStart={() => {
                setIsReplayMode(true);
                setReplayIndex(0);
                setLocalFeedbackMap({});
                setIsReplayRunning(true);
                setSelectedAlertId(undefined);
              }}
              onToggleReplayMode={() => {
                setIsReplayMode((currentValue) => {
                  const nextValue = !currentValue;
                  setIsReplayRunning(false);
                  setReplayIndex(nextValue ? 0 : alerts.length);
                  if (nextValue) {
                    setLocalFeedbackMap({});
                  }
                  return nextValue;
                });
              }}
              replayIndex={replayIndex}
              replaySpeed={replaySpeed}
              totalAlerts={alerts.length}
            />
            <KpiCards
              feedbackSummary={feedbackSummary}
              flowAlertCounts={flowAlertCounts}
              fusionSummary={fusionSummary}
              sessionKpis={sessionKpis}
            />
            <div className="operations-top-grid">
              <OperationalOverview
                alerts={sortedAlerts}
                feedbackSummary={feedbackSummary}
                flowAlertCounts={flowAlertCounts}
              />
              <LatestActivityPanel
                alerts={isReplayMode ? replayVisibleAlerts : []}
                isReplayMode={isReplayMode}
                onSelectAlert={(alert) => setSelectedAlertId(alert.id)}
                replayIndex={isReplayMode ? replayIndex : 0}
                selectedAlertId={selectedAlert?.id}
                totalAlerts={alerts.length}
              />
            </div>
            <FilterBar
              activeFilter={activeFilter}
              activeAttackType={activeAttackType}
              attackTypes={attackTypes}
              onAttackTypeChange={(attackType) => {
                setActiveAttackType(attackType);
                setSelectedAlertId(undefined);
              }}
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
                title={filterTitles[activeFilter]}
                totalDetectionRecords={sortedAlerts.length}
                selectedAlertId={selectedAlert?.id}
                onSelectAlert={(alert) => setSelectedAlertId(alert.id)}
              />
              </div>
              <AlertDetailPanel
                alert={selectedAlert}
                onApplyFeedback={applyFeedback}
                onResetFeedback={resetFeedback}
              />
            </section>
          </>
        )}

        {activeView === 'investigations' && (
          <InvestigationsPanel
            alert={selectedAlert}
            onApplyFeedback={applyFeedback}
            onResetFeedback={resetFeedback}
          />
        )}
        {activeView === 'feedback' && (
          <FeedbackSummaryPanel sessionKpis={sessionKpis} summary={feedbackSummary} />
        )}
        {activeView === 'reports' && (
          <ReportsPanel feedbackSummary={feedbackSummary} fusionSummary={fusionSummary} />
        )}
      </main>
    </div>
  );
}

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import analystArtifact from '../src/data/analyst-alerts.v1.json' with { type: 'json' };
import demoArtifact from '../src/data/adaptation-demo-scenarios.v1.json' with { type: 'json' };
import { loadValidatedAnalystArtifact } from '../src/data-contract/loadAnalystArtifact.js';
import { SESSION_PREVIEW_ACTION_POLICY } from '../src/utils/sessionPreview.js';

const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const read = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
const appSource = read('dashboard/src/App.tsx');
const queueSource = read('dashboard/src/components/AlertQueue.tsx');
const latestSource = read('dashboard/src/components/LatestActivityPanel.tsx');
const replaySource = read('dashboard/src/components/ReplayControls.tsx');
const controlsSource = read('dashboard/src/components/FeedbackControls.tsx');
const impactSource = read('dashboard/src/components/FeedbackImpactPanel.tsx');
const filterBarSource = read('dashboard/src/components/FilterBar.tsx');
const filterSource = read('dashboard/src/utils/alertFilters.ts');
const feedbackPanelSource = read('dashboard/src/components/FeedbackSummaryPanel.tsx');
const stylesSource = read('dashboard/src/styles.css');
const viteConfigSource = read('dashboard/vite.config.ts');
const pagesWorkflowSource = read('.github/workflows/deploy-dashboard-pages.yml');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function valueFingerprint(values) {
  return sha256(JSON.stringify(values));
}

function countGroundTruthFields(value) {
  const forbidden = new Set(['groundTruth', 'rawLabel', 'trueAttackType', 'mappedAttackType']);
  let count = 0;
  const visit = (node) => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== 'object') return;
    for (const [key, child] of Object.entries(node)) {
      if (forbidden.has(key)) count += 1;
      visit(child);
    }
  };
  visit(value);
  return count;
}

function activeByApprovedCriteria(alert) {
  return alert.workflow.requiresAnalystReview
    || alert.adaptation.operationalPriorityScore >= 40
    || alert.signatureEvidence.hit;
}

function activeByLegacyDecisionFallback(alert) {
  return activeByApprovedCriteria(alert)
    || (alert.automatedDetection.fusionDecision !== ''
      && alert.automatedDetection.fusionDecision !== 'LOW_RISK_BENIGN');
}

function mockResponse(body, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    async json() { return body; },
  };
}

test('1 analyst artifact is imported as a Vite URL, not bundled JSON data', () => {
  assert.match(appSource, /analyst-alerts\.v1\.json\?url/);
  assert.doesNotMatch(appSource, /from ['"]\.\/data\/analyst-alerts\.v1\.json['"]/);
});

test('2 production analyst asset URL is delegated to Vite and respects project base', () => {
  assert.match(viteConfigSource, /command === 'build' \|\| isPreview \? productionBase\(\) : '\/'/);
  assert.match(viteConfigSource, /process\.env\.VITE_BASE_PATH/);
  assert.doesNotMatch(appSource, /['"]\/data\/analyst-alerts/);
});

test('3 valid fetched analyst data passes validation before use', async () => {
  const loaded = await loadValidatedAnalystArtifact('/ids-dashboard/assets/analyst.json', {
    fetchImpl: async () => mockResponse(analystArtifact),
  });
  assert.equal(loaded, analystArtifact);
});

test('4 invalid fetched analyst data fails closed', async () => {
  await assert.rejects(
    loadValidatedAnalystArtifact('/ids-dashboard/assets/analyst.json', {
      fetchImpl: async () => mockResponse({ alerts: [] }),
    }),
    (error) => error.code === 'validation_failed',
  );
});

test('5 failed analyst request fails closed', async () => {
  await assert.rejects(
    loadValidatedAnalystArtifact('/ids-dashboard/assets/missing.json', {
      fetchImpl: async () => mockResponse(null, { ok: false, status: 404 }),
    }),
    (error) => error.code === 'request_failed' && !String(error.stack).includes('<html'),
  );
});

test('6 loading state is explicit and live', () => {
  assert.match(appSource, /Loading validated analyst data\.\.\./);
  assert.match(appSource, /aria-busy="true"/);
});

test('7 analyst-data-unavailable state is explicit', () => {
  assert.match(appSource, /Analyst data unavailable/);
  assert.match(appSource, /No unvalidated or fabricated alerts are shown/);
});

test('8 no fabricated fallback alert data is used', () => {
  assert.doesNotMatch(appSource, /fallbackAlerts|sampleAlerts|mockAlerts/);
  assert.match(appSource, /status: 'error',\s*artifact: null/s);
});

test('9 formal summary counts remain frozen', () => {
  assert.deepEqual({
    records: analystArtifact.summary.recordCount,
    matches: analystArtifact.summary.similarityMatchCount,
    eligible: analystArtifact.summary.adaptationEligibleCount,
    adaptations: analystArtifact.summary.actualAdaptationCount,
  }, { records: 995, matches: 204, eligible: 0, adaptations: 0 });
});

test('10 Active Alerts remain 524 under the approved criteria', () => {
  assert.equal(analystArtifact.alerts.filter(activeByApprovedCriteria).length, 524);
});

test('11 Detection Score fingerprint is unchanged', () => {
  assert.equal(
    valueFingerprint(analystArtifact.alerts.map((alert) => [alert.identity.id, alert.automatedDetection.detectionScore])),
    '5530d9e773e57ee7a4ce134e7054f4b8ff03c22953e7bd38aecfa315d09565c7',
  );
});

test('12 Operational Priority fingerprint is unchanged', () => {
  assert.equal(
    valueFingerprint(analystArtifact.alerts.map((alert) => [alert.identity.id, alert.adaptation.operationalPriorityScore])),
    '5530d9e773e57ee7a4ce134e7054f4b8ff03c22953e7bd38aecfa315d09565c7',
  );
});

test('13 formal queue ordering fingerprint is unchanged', () => {
  assert.equal(
    valueFingerprint(analystArtifact.alerts.map((alert) => alert.identity.id)),
    '18bb980043b2f1564801786559530d345d905f766c0c87abefe0388fea424d33',
  );
});

test('14 canonical analyst artifact bytes are unchanged', () => {
  assert.equal(
    sha256(fs.readFileSync(path.join(repoRoot, 'dashboard/src/data/analyst-alerts.v1.json'))),
    '3d13d626e5fda1a9db95423a4afbe2fe72585819c861ecbf272ee8b4a7337576',
  );
});

test('15 analyst artifact contains no ground-truth fields', () => {
  assert.equal(analystArtifact.summary.groundTruthFieldCount, 0);
  assert.equal(countGroundTruthFields(analystArtifact), 0);
});

test('16 demo IDs remain excluded from the formal queue', () => {
  const formalIds = new Set(analystArtifact.alerts.map((alert) => alert.identity.id));
  assert.ok(demoArtifact.scenarios.every((scenario) => !formalIds.has(scenario.alert.identity.id)));
});

test('17 replay UI makes no unverified arrival-time claim', () => {
  assert.doesNotMatch(`${latestSource}\n${replaySource}`, /arrival order|newest alerts|latest by timestamp/i);
  assert.match(latestSource, /artifact sequence/);
});

test('18 replay sequence is explicitly separate from risk-priority order', () => {
  assert.match(latestSource, /separate from risk-priority order/);
  assert.match(queueSource, /Operational Priority/);
});

test('19 primary queue and replay UI do not expose raw fusionDecision', () => {
  assert.doesNotMatch(queueSource, /fusionDecision/);
  assert.doesNotMatch(latestSource, /fusionDecision/);
});

test('20 Detection Score terminology remains visible', () => {
  assert.match(queueSource, /Detection Score/);
  assert.match(impactSource, /Detection Score/);
});

test('21 Operational Priority terminology remains visible', () => {
  assert.match(queueSource, /Operational Priority/);
  assert.match(impactSource, /Pipeline Operational Priority/);
});

test('22 Session Preview terminology remains explicit', () => {
  assert.match(`${queueSource}\n${impactSource}`, /Session Preview/);
  assert.doesNotMatch(impactSource, /Local analyst feedback/);
});

test('23 browser actions make no permanent persistence claim', () => {
  assert.match(controlsSource, /No backend write-back or historical-memory update/);
  assert.match(controlsSource, /Not persisted/);
  assert.doesNotMatch(controlsSource, /saved permanently|permanent audit record|model retrained/i);
});

test('24 analyst note remains session-only and non-scoring', () => {
  assert.match(controlsSource, /Session-only analyst note/);
  assert.match(controlsSource, /no scoring or similarity influence/);
});

test('25 Expected Activity session preview remains minus 15', () => {
  assert.equal(SESSION_PREVIEW_ACTION_POLICY.EXPECTED_ACTIVITY.delta, -15);
});

test('26 Uncertain remains zero-delta and review-required', () => {
  assert.equal(SESSION_PREVIEW_ACTION_POLICY.UNCERTAIN.delta, 0);
  assert.equal(SESSION_PREVIEW_ACTION_POLICY.UNCERTAIN.forceReview, true);
});

test('27 Duplicate remains a zero-delta workflow action', () => {
  assert.equal(SESSION_PREVIEW_ACTION_POLICY.DUPLICATE.delta, 0);
  assert.equal(SESSION_PREVIEW_ACTION_POLICY.DUPLICATE.category, 'workflow');
});

test('28 ML Unavailable remains a dedicated filter', () => {
  assert.match(filterBarSource, /key: 'ml-unavailable', label: 'ML Unavailable'/);
  assert.match(filterSource, /case 'ml-unavailable'/);
});

test('29 four low-risk ML-unavailable records remain outside Active Alerts', () => {
  const excluded = analystArtifact.alerts.filter((alert) => (
    activeByLegacyDecisionFallback(alert) && !activeByApprovedCriteria(alert)
  ));
  assert.deepEqual(excluded.map((alert) => alert.identity.id), ['AL-0376', 'AL-0423', 'AL-0447', 'AL-0984']);
});

test('30 responsive queue retains mobile triage fields without horizontal minimum width', () => {
  for (const label of ['Alert ID', 'Operational Priority', 'Attack Type', 'Detector State', 'Review / Workflow']) {
    assert.match(queueSource, new RegExp(`data-label="${label}"`));
  }
  assert.match(stylesSource, /@media \(max-width: 760px\)[\s\S]*?\.alert-table \{\s*min-width: 0;/);
});

test('31 keyboard queue interaction and visible focus remain intact', () => {
  assert.match(queueSource, /tabIndex=\{0\}/);
  assert.match(queueSource, /event\.key === 'Enter' \|\| event\.key === ' '/);
  assert.match(stylesSource, /\.alert-table \.alert-row:focus-visible/);
});

test('32 active controls expose semantic selection state', () => {
  assert.match(filterBarSource, /aria-pressed=\{activeFilter === filter\.key\}/);
  assert.match(replaySource, /aria-pressed=\{isReplayMode\}/);
  assert.match(replaySource, /aria-pressed=\{replaySpeed === speed\}/);
});

test('33 GitHub Pages production base follows the repository name with a local fallback', () => {
  assert.match(viteConfigSource, /'\/ids-dashboard\/'/);
  assert.match(pagesWorkflowSource, /VITE_BASE_PATH: \/\$\{\{ github\.event\.repository\.name \}\}\//);
});

test('34 demo metadata still states no actual XGBoost inference', () => {
  assert.equal(demoArtifact.generationMetadata.actualXgboostInference, false);
  assert.match(feedbackPanelSource, /no actual XGBoost inference/i);
});

test('35 controlled demo scores remain frozen', () => {
  assert.deepEqual(demoArtifact.scenarios.map(({ scenarioId, alert }) => [
    scenarioId,
    alert.automatedDetection.detectionScore,
    alert.adaptation.operationalPriorityScore,
  ]), [
    ['cold_start', 72, 72],
    ['repeated_false_positive', 80, 55],
    ['confirmed_threat', 59, 74],
    ['conflicting_history', 70, 70],
    ['guardrail_protection', 90, 70],
    ['ml_unavailable', 80, 80],
  ]);
});

test('36 evaluator-summary failure is isolated from operational analyst data', () => {
  assert.match(appSource, /Evaluation summary unavailable/);
  assert.doesNotMatch(appSource, /!analystArtifact \|\| !evaluatorArtifact/);
});

test('37 demo-artifact failure remains isolated and explicit', () => {
  assert.match(feedbackPanelSource, /Demonstration data unavailable/);
  assert.match(appSource, /demoErrors=\{demoArtifactValidation\.errors\}/);
});

test('38 zero filter matches render a meaningful empty state', () => {
  assert.match(queueSource, /No detection records match the current filters/);
});

test('39 asynchronously loaded alerts invalidate all derived queue state', () => {
  assert.match(
    appSource,
    /\(\) => applySessionPreviewOverrides\(alerts, localFeedbackMap\),\s*\[alerts, localFeedbackMap\]/s,
  );
});

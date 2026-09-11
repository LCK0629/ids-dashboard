import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';

import analystArtifact from '../src/data/analyst-alerts.v1.json' with { type: 'json' };
import demoArtifact from '../src/data/adaptation-demo-scenarios.v1.json' with { type: 'json' };
import {
  calculateSessionPreview,
  LEARNING_FEEDBACK_ACTIONS,
  normalizeSessionNote,
  SESSION_NOTE_MAX_LENGTH,
  SESSION_PREVIEW_ACTION_POLICY,
  WORKFLOW_ACTIONS,
} from '../src/utils/sessionPreview.js';
import { getDetectorStatePresentation } from '../src/utils/automatedEvidence.js';
import {
  getHistoricalAdjustmentPresentation,
  getReviewWorkflowPresentation,
} from '../src/utils/analystWorkflow.js';

const require = createRequire(import.meta.url);
const { applyDirectFeedback } = require('../../stage-5/core/feedback-engine.js');
const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const queueSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/AlertQueue.tsx'), 'utf8');
const latestActivitySource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/LatestActivityPanel.tsx'), 'utf8');
const controlsSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/FeedbackControls.tsx'), 'utf8');
const scoreSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/ScoreComparison.tsx'), 'utf8');
const impactSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/FeedbackImpactPanel.tsx'), 'utf8');
const filterSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/utils/alertFilters.ts'), 'utf8');
const filterBarSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/components/FilterBar.tsx'), 'utf8');
const feedbackSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/utils/feedback.ts'), 'utf8');
const stylesSource = fs.readFileSync(path.join(repoRoot, 'dashboard/src/styles.css'), 'utf8');

function workflowAlert(overrides = {}) {
  return {
    id: 'AL-WORKFLOW',
    detectionScore: 50,
    operationalPriorityScore: 50,
    stage5CurrentRiskScore: 50,
    currentRiskScore: 50,
    fusionAttackType: 'DoS',
    fusionDecision: 'ML_ONLY_HIGH_CONFIDENCE',
    fusionConfidenceLevel: 'Medium',
    signatureSeverity: null,
    requiresAnalystReview: false,
    ...overrides,
  };
}

function stage5Result(alert, action) {
  const policy = SESSION_PREVIEW_ACTION_POLICY[action];
  return applyDirectFeedback(alert, {
    feedbackId: `FB-${action}`,
    alertId: alert.id,
    analystId: 'TEST-ANALYST',
    timestamp: '2026-09-11T00:00:00.000Z',
    eventType: 'feedback_submitted',
    feedbackType: policy.stage5FeedbackType,
  });
}

function expectedStage5Review(result) {
  return Boolean(result.forceReview || result.operationalPriorityScore >= 70);
}

function sha256(values) {
  return crypto.createHash('sha256').update(JSON.stringify(values)).digest('hex');
}

function countForbiddenGroundTruthFields(value) {
  const forbidden = new Set(['groundTruth', 'rawLabel', 'trueAttackType', 'mappedAttackType']);
  let count = 0;
  function visit(node) {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== 'object') return;
    for (const [key, child] of Object.entries(node)) {
      if (forbidden.has(key)) count += 1;
      visit(child);
    }
  }
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

test('1 queue makes Operational Priority the first score column', () => {
  assert.ok(queueSource.indexOf('<th>Operational Priority</th>') < queueSource.indexOf('<th>Detection Score</th>'));
  assert.match(queueSource, /risk-badge.*operationalPriorityScore/s);
});

test('2 Detection Score remains visible as a secondary queue value', () => {
  assert.match(queueSource, /secondary-score.*alert\.detectionScore/s);
});

test('3 raw fusionDecision is not a primary queue column', () => {
  assert.doesNotMatch(queueSource, /<th>Decision<\/th>/);
  assert.doesNotMatch(queueSource, /alert\.fusionDecision/);
});

test('4 queue uses the friendly detector-state presenter', () => {
  assert.match(queueSource, /getDetectorStatePresentation\(analystAlert\)/);
});

test('5 detector disagreement has a recognizable friendly label', () => {
  const alert = analystArtifact.alerts.find((item) => item.automatedDetection.detectorState === 'disagreement');
  assert.ok(alert);
  assert.match(getDetectorStatePresentation(alert).label, /disagree|Signature matched/i);
});

test('6 ML unavailable has a recognizable friendly label', () => {
  const alert = analystArtifact.alerts.find((item) => item.mlEvidence.recordPresent && !item.mlEvidence.evidenceAvailable);
  assert.ok(alert);
  assert.match(getDetectorStatePresentation(alert).label, /ML.*unavailable|ML prediction unavailable/i);
});

test('7 historical HITL state is separate from session preview state', () => {
  assert.match(queueSource, /getHistoricalAdjustmentPresentation/);
  assert.match(queueSource, /Session: \{alert\.localFeedbackLabel\}/);
  assert.match(scoreSource, /Historical HITL adjustment/);
  assert.match(scoreSource, /Session Preview Priority/);
});

test('8 Learning Feedback contains exactly the intended actions', () => {
  assert.deepEqual([...LEARNING_FEEDBACK_ACTIONS], ['CONFIRMED_THREAT', 'FALSE_POSITIVE', 'EXPECTED_ACTIVITY']);
});

test('9 Workflow Actions contains exactly the intended actions', () => {
  assert.deepEqual([...WORKFLOW_ACTIONS], ['NEEDS_INVESTIGATION', 'UNCERTAIN', 'ESCALATED', 'DUPLICATE']);
});

for (const [number, action, delta, forceReview] of [
  [10, 'EXPECTED_ACTIVITY', -15, false],
  [11, 'FALSE_POSITIVE', -30, false],
  [12, 'CONFIRMED_THREAT', 10, true],
  [13, 'ESCALATED', 15, true],
  [14, 'NEEDS_INVESTIGATION', 0, true],
  [15, 'UNCERTAIN', 0, true],
  [16, 'DUPLICATE', 0, false],
]) {
  test(`${number} ${action} session semantics match the approved policy`, () => {
    const policy = SESSION_PREVIEW_ACTION_POLICY[action];
    assert.equal(policy.delta, delta);
    assert.equal(policy.forceReview, forceReview);
    if (action === 'DUPLICATE') assert.equal(policy.category, 'workflow');
  });
}

test('17 all session actions align with Stage 5 direct-feedback scores and review semantics', () => {
  for (const action of [...LEARNING_FEEDBACK_ACTIONS, ...WORKFLOW_ACTIONS]) {
    const alert = workflowAlert();
    const preview = calculateSessionPreview(alert, action);
    const authority = stage5Result(alert, action);
    assert.equal(preview.sessionPreviewPriorityScore, authority.operationalPriorityScore, action);
    assert.equal(preview.reviewRequired, expectedStage5Review(authority), action);
  }
});

test('18 Detection Score remains immutable under every session preview action', () => {
  for (const action of Object.keys(SESSION_PREVIEW_ACTION_POLICY)) {
    const alert = workflowAlert();
    const before = structuredClone(alert);
    calculateSessionPreview(alert, action);
    assert.deepEqual(alert, before);
    assert.equal(alert.detectionScore, 50);
  }
});

test('19 pipeline Operational Priority is returned separately and preserved', () => {
  const result = calculateSessionPreview(workflowAlert({ stage5CurrentRiskScore: 62 }), 'FALSE_POSITIVE');
  assert.equal(result.pipelineOperationalPriorityScore, 62);
  assert.equal(result.sessionPreviewPriorityScore, 32);
});

test('20 local preview changes only the session-preview priority field', () => {
  assert.match(feedbackSource, /sessionPreviewPriorityScore: preview\.sessionPreviewPriorityScore/);
  assert.match(feedbackSource, /operationalPriorityScore: stage5CurrentRiskScore/);
  assert.doesNotMatch(feedbackSource, /operationalPriorityScore: preview\.sessionPreviewPriorityScore/);
});

test('21 clearing a session preview restores the pipeline-derived alert', () => {
  assert.match(feedbackSource, /if \(!override\) \{\s*return baseAlert;/s);
  assert.match(feedbackSource, /sessionPreviewPriorityScore: undefined/);
});

test('22 clear wording does not claim historical feedback deletion', () => {
  assert.match(controlsSource, /Clear Session Preview/);
  assert.match(controlsSource, /does not delete historical feedback/);
  assert.doesNotMatch(controlsSource, /Reset Feedback/);
});

test('23 session note has no scoring influence', () => {
  const first = calculateSessionPreview(workflowAlert(), 'FALSE_POSITIVE');
  const note = normalizeSessionNote('  approved maintenance window  ');
  const second = calculateSessionPreview(workflowAlert(), 'FALSE_POSITIVE');
  assert.equal(note, 'approved maintenance window');
  assert.deepEqual(first, second);
});

test('24 session note is excluded from similarity and historical HITL input', () => {
  assert.doesNotMatch(feedbackSource, /sessionNote|analystNote/);
  assert.match(controlsSource, /no scoring or similarity influence/);
});

test('25 session note length is bounded and whitespace is trimmed', () => {
  assert.equal(SESSION_NOTE_MAX_LENGTH, 500);
  assert.equal(normalizeSessionNote(`  ${'x'.repeat(600)}  `).length, 498);
  assert.equal(normalizeSessionNote('  context  '), 'context');
});

test('26 local action does not mutate canonical formal HITL diagnostics', () => {
  const before = JSON.stringify(analystArtifact.alerts[0].adaptation);
  calculateSessionPreview(workflowAlert(), 'CONFIRMED_THREAT');
  assert.equal(JSON.stringify(analystArtifact.alerts[0].adaptation), before);
});

test('27 mobile queue preserves the five required triage labels without horizontal minimum width', () => {
  for (const label of ['Alert ID', 'Operational Priority', 'Attack Type', 'Detector State', 'Review / Workflow']) {
    assert.match(queueSource, new RegExp(`data-label="${label}"`));
  }
  assert.match(stylesSource, /@media \(max-width: 760px\)[\s\S]*?\.alert-table \{\s*min-width: 0;/);
  assert.match(stylesSource, /content: attr\(data-label\)/);
});

test('28 queue rows are keyboard operable with Enter and Space', () => {
  assert.match(queueSource, /tabIndex=\{0\}/);
  assert.match(queueSource, /event\.key === 'Enter' \|\| event\.key === ' '/);
  assert.match(queueSource, /aria-selected/);
});

test('29 analyst-facing artifact contains no per-alert ground truth', () => {
  assert.equal(countForbiddenGroundTruthFields(analystArtifact), 0);
  assert.equal(analystArtifact.summary.groundTruthFieldCount, 0);
});

test('30 demonstration alerts remain outside the formal queue artifact', () => {
  const formalIds = new Set(analystArtifact.alerts.map((alert) => alert.identity.id));
  for (const scenario of demoArtifact.scenarios) assert.equal(formalIds.has(scenario.alert.identity.id), false);
});

test('31 formal Stage 5 counts remain unchanged', () => {
  assert.deepEqual({
    records: analystArtifact.summary.recordCount,
    matches: analystArtifact.summary.similarityMatchCount,
    eligible: analystArtifact.summary.adaptationEligibleCount,
    adaptations: analystArtifact.summary.actualAdaptationCount,
  }, { records: 995, matches: 204, eligible: 0, adaptations: 0 });
});

test('32 formal Detection Scores retain their approved fingerprint', () => {
  assert.equal(
    sha256(analystArtifact.alerts.map((alert) => [alert.identity.id, alert.automatedDetection.detectionScore])),
    '5530d9e773e57ee7a4ce134e7054f4b8ff03c22953e7bd38aecfa315d09565c7',
  );
});

test('33 formal Operational Priorities retain their approved fingerprint', () => {
  assert.equal(
    sha256(analystArtifact.alerts.map((alert) => [alert.identity.id, alert.adaptation.operationalPriorityScore])),
    '5530d9e773e57ee7a4ce134e7054f4b8ff03c22953e7bd38aecfa315d09565c7',
  );
});

test('34 formal queue ordering retains its approved fingerprint', () => {
  assert.equal(
    sha256(analystArtifact.alerts.map((alert) => alert.identity.id)),
    '18bb980043b2f1564801786559530d345d905f766c0c87abefe0388fea424d33',
  );
});

test('35 active queue excludes records admitted only by raw decision-code fallback', () => {
  assert.equal(analystArtifact.alerts.filter(activeByLegacyDecisionFallback).length, 528);
  assert.equal(analystArtifact.alerts.filter(activeByApprovedCriteria).length, 524);
  assert.doesNotMatch(filterSource, /decision !== '' && decision !== 'LOW_RISK_BENIGN'/);
});

test('36 excluded decision-only records are four low-risk ML-unavailable records', () => {
  const excluded = analystArtifact.alerts.filter((alert) => (
    activeByLegacyDecisionFallback(alert) && !activeByApprovedCriteria(alert)
  ));
  assert.deepEqual(excluded.map((alert) => alert.identity.id), ['AL-0376', 'AL-0423', 'AL-0447', 'AL-0984']);
  assert.ok(excluded.every((alert) => alert.automatedDetection.fusionDecision === 'LOW_RISK_ML_UNAVAILABLE'));
  assert.ok(excluded.every((alert) => alert.adaptation.operationalPriorityScore === 0));
});

test('37 ML Unavailable remains available as a dedicated analyst filter', () => {
  assert.match(filterBarSource, /key: 'ml-unavailable', label: 'ML Unavailable'/);
  assert.match(filterSource, /case 'ml-unavailable'/);
});

test('38 session action buttons expose active state and semantic grouping', () => {
  assert.match(controlsSource, /<fieldset className="feedback-action-group"/);
  assert.match(controlsSource, /aria-pressed=\{activeAction === action\}/);
  assert.match(controlsSource, /label="Learning Feedback"/);
  assert.match(controlsSource, /label="Workflow Actions"/);
});

test('39 workflow actions render workflow status rather than learning labels', () => {
  for (const [action, label] of [
    ['NEEDS_INVESTIGATION', 'Needs investigation'],
    ['UNCERTAIN', 'Uncertain'],
    ['ESCALATED', 'Escalated'],
    ['DUPLICATE', 'Duplicate'],
  ]) {
    assert.equal(getReviewWorkflowPresentation({ localFeedbackAction: action }, undefined).label, label);
  }
});

test('40 HITL queue labels include no-history, no-applicable-history, and conflict states', () => {
  const base = {
    proposedAdjustment: 0, cappedAdjustment: 0, appliedAdjustment: 0,
    guardrailsApplied: [], priorityAdjusted: false, conflictDetected: false, eligible: false,
    diagnostics: { evaluated: true, historicalFeedback: {}, similarity: {} },
  };
  assert.equal(getHistoricalAdjustmentPresentation({
    ...base,
    diagnostics: { ...base.diagnostics, historicalFeedback: { candidateLearningFeedbackCount: 0 } },
  }).label, 'No historical adjustment');
  assert.equal(getHistoricalAdjustmentPresentation({
    ...base,
    diagnostics: {
      ...base.diagnostics,
      historicalFeedback: { candidateLearningFeedbackCount: 2 }, similarity: { matchedCount: 0 },
    },
  }).label, 'No applicable history');
  assert.equal(getHistoricalAdjustmentPresentation({ ...base, conflictDetected: true }).label, 'Conflict / no adjustment');
});

test('41 score panels avoid ambiguous Current Risk Score wording', () => {
  assert.doesNotMatch(scoreSource, /Current Risk Score/i);
  assert.doesNotMatch(impactSource, /Current Risk Score/i);
  assert.match(impactSource, /Pipeline Operational Priority/);
});

test('42 session controls make non-persistence explicit without claiming learning occurred', () => {
  assert.match(controlsSource, /Browser preview only/);
  assert.match(controlsSource, /Not persisted/);
  assert.doesNotMatch(controlsSource, /feedback saved|system learned permanently|model retrained/i);
});

test('43 duplicate is workflow-only and never implies false positive', () => {
  const duplicate = SESSION_PREVIEW_ACTION_POLICY.DUPLICATE;
  assert.equal(duplicate.category, 'workflow');
  assert.equal(duplicate.delta, 0);
  assert.doesNotMatch(duplicate.reason, /false positive|benign/i);
});

test('44 critical and Infiltration session guardrails preserve Stage 5 floors', () => {
  const critical = calculateSessionPreview(workflowAlert({ stage5CurrentRiskScore: 90, fusionConfidenceLevel: 'Critical' }), 'FALSE_POSITIVE');
  const infiltration = calculateSessionPreview(workflowAlert({ stage5CurrentRiskScore: 80, fusionAttackType: 'Infiltration' }), 'FALSE_POSITIVE');
  assert.equal(critical.sessionPreviewPriorityScore, 70);
  assert.equal(infiltration.sessionPreviewPriorityScore, 75);
  assert.equal(critical.reviewRequired, true);
  assert.equal(infiltration.reviewRequired, true);
});

test('45 Latest Activity also avoids raw fusion decision codes', () => {
  assert.match(latestActivitySource, /getDetectorStatePresentation\(analystAlert\)/);
  assert.doesNotMatch(latestActivitySource, /alert\.fusionDecision/);
});

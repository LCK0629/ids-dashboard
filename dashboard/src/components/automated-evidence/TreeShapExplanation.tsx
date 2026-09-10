import type { AnalystAlertV1, ShapFeatureContribution } from '../../types/dashboardData';
import {
  SHAP_HELPER_TEXT,
  SHAP_NON_CAUSAL_TEXT,
  formatFeatureValue,
  formatSignedShap,
  getTreeShapPresentation,
  normalizeShapGroups,
  shapDirectionLabel,
} from '../../utils/automatedEvidence.js';

interface TreeShapExplanationProps {
  mlEvidence: AnalystAlertV1['mlEvidence'];
}

interface ContributionListProps {
  features: Array<ShapFeatureContribution & { visualWidth: number }>;
  predictedClass: string | null;
  title: string;
  type: 'supporting' | 'opposing';
}

function ContributionList({ features, predictedClass, title, type }: ContributionListProps) {
  return (
    <section className={`shap-group shap-group-${type}`}>
      <h5>{title}</h5>
      {features.length > 0 ? (
        <ul className="shap-list">
          {features.map((feature) => (
            <li className="shap-row" key={`${type}-${feature.featureName}`}>
              <div className="shap-row-heading">
                <strong>{feature.featureName}</strong>
                <span>Value: {formatFeatureValue(feature.featureValue)}</span>
              </div>
              <div className="shap-contribution-line">
                <span className="shap-direction-label">{shapDirectionLabel(feature.direction, predictedClass)}</span>
                <b>{formatSignedShap(feature.shapContribution)}</b>
              </div>
              <div className="shap-diverging-track" aria-hidden="true">
                <span
                  className={`shap-bar shap-bar-${type}`}
                  style={{ width: `${feature.visualWidth / 2}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      ) : <p className="helper-text">No {type} features were supplied.</p>}
    </section>
  );
}

export function TreeShapExplanation({ mlEvidence }: TreeShapExplanationProps) {
  const presentation = getTreeShapPresentation(mlEvidence);
  const explanation = mlEvidence.explanation;

  if (!presentation.available || explanation.status !== 'available') {
    return (
      <section className="tree-shap-panel tree-shap-unavailable" aria-live="polite">
        <div className="evidence-section-heading">
          <div>
            <span>ML explanation</span>
            <h4>{presentation.title}</h4>
          </div>
          <span className="evidence-state-pill warning">Unavailable</span>
        </div>
        <p>{presentation.detail}</p>
        <p className="helper-text">The ML prediction remains unchanged when its explanation is unavailable.</p>
      </section>
    );
  }

  const normalized = normalizeShapGroups(
    explanation.topSupportingFeatures,
    explanation.topOpposingFeatures
  );
  const predictedClass = explanation.explainedClass || mlEvidence.predictedAttackType;

  return (
    <section className="tree-shap-panel" aria-labelledby="tree-shap-title">
      <div className="evidence-section-heading">
        <div>
          <span>Predicted-class explanation</span>
          <h4 id="tree-shap-title">{presentation.title}</h4>
        </div>
        <span className="evidence-state-pill matched">TreeSHAP available</span>
      </div>
      <p>{SHAP_HELPER_TEXT}</p>
      <p className="evidence-caution">{SHAP_NON_CAUSAL_TEXT}</p>
      <div className="shap-axis-labels" aria-hidden="true">
        <span>Opposes prediction</span>
        <span>Supports prediction</span>
      </div>
      <div className="shap-groups">
        <ContributionList
          features={normalized.supporting}
          predictedClass={predictedClass}
          title="Supporting features"
          type="supporting"
        />
        <ContributionList
          features={normalized.opposing}
          predictedClass={predictedClass}
          title="Opposing features"
          type="opposing"
        />
      </div>
      <p className="helper-text">
        Bar width is relative only within this displayed explanation. The signed number is the original raw-margin SHAP contribution and should not be compared between alerts as an absolute risk scale.
      </p>
    </section>
  );
}

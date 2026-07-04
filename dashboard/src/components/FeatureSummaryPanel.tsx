import type { FeedbackAdjustedAlert } from '../types/alerts';
import { buildFeatureGroups } from '../utils/investigation';

interface FeatureSummaryPanelProps {
  alert: FeedbackAdjustedAlert;
}

export function FeatureSummaryPanel({ alert }: FeatureSummaryPanelProps) {
  const groups = buildFeatureGroups(alert);

  return (
    <section className="feature-summary-grid" aria-label="Flow feature summary">
      {groups.map((group) => (
        <article className="feature-card" key={group.title}>
          <h3>{group.title}</h3>
          <div className="feature-list">
            {group.items.map((item) => (
              <div className="feature-item" key={item.label}>
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </article>
      ))}
    </section>
  );
}

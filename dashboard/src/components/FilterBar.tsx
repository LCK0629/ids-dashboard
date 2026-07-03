import type { FilterKey } from '../types/alerts';

interface FilterOption {
  key: FilterKey;
  label: string;
}

const filters: FilterOption[] = [
  { key: 'all', label: 'All' },
  { key: 'requires-review', label: 'Requires Review' },
  { key: 'feedback-applied', label: 'Feedback Applied' },
  { key: 'high-risk', label: 'High Risk' },
  { key: 'infiltration', label: 'Infiltration' },
  { key: 'signature-ml-disagree', label: 'Signature/ML Disagree' },
  { key: 'guardrail-applied', label: 'Guardrail Applied' },
  { key: 'benign', label: 'Benign' },
  { key: 'malicious', label: 'Malicious' },
];

interface FilterBarProps {
  activeFilter: FilterKey;
  onFilterChange: (filter: FilterKey) => void;
  visibleCount: number;
  totalCount: number;
}

export function FilterBar({ activeFilter, onFilterChange, visibleCount, totalCount }: FilterBarProps) {
  return (
    <section className="filter-bar" aria-label="Alert filters">
      <div>
        <strong>{visibleCount}</strong>
        <span> of {totalCount} alerts shown</span>
      </div>
      <div className="filter-buttons">
        {filters.map((filter) => (
          <button
            className={activeFilter === filter.key ? 'active' : ''}
            key={filter.key}
            onClick={() => onFilterChange(filter.key)}
            type="button"
          >
            {filter.label}
          </button>
        ))}
      </div>
    </section>
  );
}

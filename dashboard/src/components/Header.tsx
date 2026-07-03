interface HeaderProps {
  activeLabel: string;
}

export function Header({ activeLabel }: HeaderProps) {
  return (
    <header className="topbar">
      <div>
        <p className="eyebrow">CSIT-26-S3-07</p>
        <h1>Human-in-the-Loop IDS Dashboard</h1>
        <p>Hybrid signature, ML, fusion, and analyst-feedback alert prioritisation</p>
      </div>
      <div className="topbar-actions">
        <div className="status-pill">Stage 6 Dashboard Integration</div>
        <div className="status-pill muted">Static JSON dashboard</div>
        <div className="status-pill warning">Not live packet capture</div>
        <div className="view-pill">{activeLabel}</div>
      </div>
    </header>
  );
}

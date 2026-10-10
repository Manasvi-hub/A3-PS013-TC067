from pathlib import Path

import typer

app = typer.Typer(help="Forensic Timeline & Evidence Collection Tool")

# Person A's commands
try:
    from .cli_evidence import evidence_app
    app.add_typer(evidence_app, name="evidence", hidden=True)
    for cmd in evidence_app.registered_commands:
        app.registered_commands.append(cmd)
except ImportError:
    pass

# Person B's commands will be added here
try:
    from .cli_analysis import analysis_app  # type: ignore[import]
    for cmd in analysis_app.registered_commands:
        app.registered_commands.append(cmd)
except ImportError:
    pass


@app.command()
def run_all(
    scenarios_dir: Path = typer.Option(
        Path("scenarios"), "--scenarios", help="Path to scenarios/ directory"
    ),
    cases_dir: Path = typer.Option(
        Path("cases"), "--cases", help="Output cases/ directory"
    ),
    collector: str = typer.Option("run-all", "--collector", help="Collector label"),
):
    """Convenience: run ingest -> build -> skew on every scenario."""
    from .build import build as do_build
    from .ingest import ingest as do_ingest
    from .skew import skew as do_skew

    if not scenarios_dir.exists() or not any(scenarios_dir.iterdir()):
        typer.echo("No scenarios found")
        raise typer.Exit(0)

    ran = 0
    for scenario in sorted(scenarios_dir.iterdir()):
        sources_json = scenario / "sources.json"
        if not scenario.is_dir() or not sources_json.exists():
            continue

        import json
        with open(sources_json, encoding="utf-8") as f:
            spec = json.load(f)
        case_id = spec.get("case_id", scenario.name)
        case_dir = cases_dir / case_id

        typer.echo(f"\n=== Scenario: {case_id} ===")

        typer.echo("  ingest ...")
        do_ingest(case_dir, sources_json, collector)

        typer.echo("  build ...")
        do_build(case_dir)

        typer.echo("  skew ...")
        do_skew(case_dir)

        # Try report (Person B) — silently skip if not available
        try:
            from .report import generate_report  # type: ignore[import]
            typer.echo("  report ...")
            generate_report(case_dir)
        except ImportError:
            pass

        ran += 1

    if ran == 0:
        typer.echo("No scenarios found")
    else:
        typer.echo(f"\nDone. Ran {ran} scenario(s).")


if __name__ == "__main__":
    app()

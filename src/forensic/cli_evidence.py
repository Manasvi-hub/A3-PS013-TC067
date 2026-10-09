import typer
from pathlib import Path

evidence_app = typer.Typer()

@evidence_app.command()
def ingest(case: Path = typer.Option(...), sources: Path = typer.Option(...), collector: str = typer.Option(...)):
    """Ingest sources into the case directory."""
    from .ingest import ingest as do_ingest
    do_ingest(case, sources, collector)
    typer.echo("Ingest complete.")

@evidence_app.command()
def verify(case: Path = typer.Option(...)):
    """Verify evidence integrity."""
    from .ingest import verify as do_verify
    import sys
    if do_verify(case):
        typer.echo("Verification passed.")
    else:
        sys.exit(1)

@evidence_app.command()
def build(case: Path = typer.Option(...)):
    """Build the database from evidence."""
    from .build import build as do_build
    do_build(case)

@evidence_app.command()
def skew(case: Path = typer.Option(...), reference: str = typer.Option(None), offset: str = typer.Option(None)):
    """Estimate or manually set clock skew."""
    from .skew import skew as do_skew
    do_skew(case, reference, offset)

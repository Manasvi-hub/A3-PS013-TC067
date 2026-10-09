import typer

from forensic.cli_analysis import app as analysis_app
from forensic.cli_evidence import app as evidence_app

app = typer.Typer()
app.add_typer(evidence_app)
app.add_typer(analysis_app)

if __name__ == "__main__":
    app()

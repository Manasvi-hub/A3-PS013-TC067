import typer

app = typer.Typer(help="Forensic Timeline & Evidence Collection Tool")

# Person A's commands
try:
    from .cli_evidence import evidence_app
    app.add_typer(evidence_app, name="evidence", hidden=True)
    # Actually, as per contract, they are root commands, so we should merge the apps or add commands directly.
    # We will register them in cli.py by importing the functions if needed, or by registering evidence_app without a namespace.
    # Typer allows merging apps or adding commands directly. We'll use app.registered_commands.extend
    for cmd in evidence_app.registered_commands:
        app.registered_commands.append(cmd)
except ImportError:
    pass

# Person B's commands will be added here
try:
    from .cli_analysis import analysis_app
    for cmd in analysis_app.registered_commands:
        app.registered_commands.append(cmd)
except ImportError:
    pass

@app.command()
def run_all():
    """Convenience: run all steps on all scenarios."""
    typer.echo("Not implemented yet.")

if __name__ == "__main__":
    app()

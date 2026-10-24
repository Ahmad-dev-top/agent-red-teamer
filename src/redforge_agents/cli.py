"""Command-line entry point.

    redforge-agents validate <target.yaml>          # validate target + seed library
    redforge-agents seeds                           # list loaded attack seeds
    redforge-agents scan <target.yaml> [--adapter]  # run the campaign, print + save the report

With --adapter stub (the default when no endpoint is reachable) the whole loop
runs offline against scripted responses — useful for wiring and demos. Use
--adapter http to hit a real target endpoint.
"""

from __future__ import annotations

import typer

from redforge_agents.adapters.base import build_adapter
from redforge_agents.config import settings
from redforge_agents.logging_conf import configure_logging
from redforge_agents.schemas import AdapterKind

app = typer.Typer(add_completion=False, help="RedForge Agents — red-team your AI agents")


@app.command()
def validate(target: str) -> None:
    """Validate a target config and the seed library; report counts."""
    configure_logging()
    from redforge_agents.seeds import load_seeds
    from redforge_agents.target_loader import load_target

    t = load_target(target)
    atks = load_seeds(settings.seeds_dir)
    typer.echo(f"target OK: {t.name} ({t.id})  adapter={t.adapter.value}  tools={len(t.tools)}")
    typer.echo(f"seeds OK: {len(atks)} attacks across "
               f"{len({a.category for a in atks})} categories")


@app.command()
def seeds() -> None:
    """List the attack seeds in the library."""
    configure_logging()
    from redforge_agents.seeds import load_seeds

    for a in load_seeds(settings.seeds_dir):
        typer.echo(f"{a.id:<28} {a.category.value:<26} {a.owasp.value}  proof={a.success.proof.value}")


@app.command()
def scan(
    target: str,
    adapter: str = typer.Option("stub", "--adapter", help="stub | http"),
    assurance: bool = typer.Option(False, "--assurance", help="also write an assurance report"),
) -> None:
    """Run the attack campaign against the target and print the report."""
    configure_logging()
    settings.ensure_dirs()
    from redforge_agents.campaign import run_campaign
    from redforge_agents.reporting import report_table, save_report
    from redforge_agents.seeds import load_seeds
    from redforge_agents.target_loader import load_target

    t = load_target(target)
    atks = load_seeds(settings.seeds_dir)
    adp = build_adapter(AdapterKind(adapter))
    report = run_campaign(t, atks, adp)

    typer.echo(report_table(report))
    out = settings.reports_dir / f"{t.id}.json"
    save_report(report, out)
    from redforge_agents.storage import Storage

    run_id = Storage(settings.db_path).save_report(report)
    typer.echo(f"\nsaved {out}")
    typer.echo(f"saved sqlite {settings.db_path} run {run_id}")
    if assurance:
        from redforge_agents.assurance import assurance_report

        md = settings.reports_dir / f"{t.id}-assurance.md"
        md.write_text(assurance_report(report), encoding="utf-8")
        typer.echo(assurance_report(report))
        typer.echo(f"\nsaved {md}")


@app.command()
def runs() -> None:
    """List persisted scans and the ASR table stored for each."""
    configure_logging()
    from redforge_agents.reporting import format_asr_table
    from redforge_agents.storage import Storage

    stored = Storage(settings.db_path).list_runs()
    if not stored:
        typer.echo("no persisted runs")
        return
    for summary in stored:
        typer.echo(
            f"{summary.id}  {summary.created_at}  {summary.target_name} "
            f"({summary.target_id})  findings={summary.findings_count}"
        )
        typer.echo("Attack success rate by category:")
        typer.echo(format_asr_table(summary.scores))
        typer.echo("")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

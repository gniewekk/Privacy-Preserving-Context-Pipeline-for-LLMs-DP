"""Interaktywna prezentacja CLI (Osoba A): podgląd krok po kroku Inbound Pipeline.

Pokazuje dokładnie, co dzieje się z promptem (tekst, PDF lub ToolCall),
zanim trafi on do zewnętrznego LLM.

Uruchomienie:
    PYTHONPATH=src .venv/bin/python presentation/demo_cli.py
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

# Pozwala uruchomić skrypt bezpośrednio bez ręcznego ustawiania PYTHONPATH=src
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.prompt import Prompt  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402
from sample_pdfs import ensure_sample_pdfs  # noqa: E402

from detectors import (  # noqa: E402
    ContextRuleEnhancer,
    EnglishTransformerNERDetector,
    HeuristicPIIDetector,
    PIIDetector,
    PolishTransformerNERDetector,
    RegexPIIDetector,
)
from domain.exceptions import HardStopError  # noqa: E402
from domain.models import (  # noqa: E402
    AuditEvent,
    AuditLevel,
    DataClass,
    DocumentAttachment,
    EndpointMetadata,
    EntityType,
    PDFExtractionPolicy,
    SecurityPrincipal,
    ToolCall,
)
from pipeline import (  # noqa: E402
    Pipeline,
    PipelineBuilder,
    PipelineContext,
)
from strategies import MaskingStrategy, TokenizationStrategy  # noqa: E402

console = Console()


class DemoAuditWriter:
    """Lokalny AuditWriter przechowujący niemutowalne wpisy zdarzeń (bez surowego PII)."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    def events(self) -> Sequence[AuditEvent]:
        return tuple(self._events)


class DemoResidencyPolicyEngine:
    """Przykładowa polityka zgodności EU: dane MEDICAL nie mogą opuścić EOG."""

    def is_allowed(self, data_class: DataClass, endpoint: EndpointMetadata) -> bool:
        if data_class == DataClass.MEDICAL:
            return endpoint.is_eu_compliant
        return True


ENDPOINTS: dict[str, EndpointMetadata] = {
    "eu": EndpointMetadata(
        provider_id="azure-openai-eu",
        region="eu-central-1 (Frankfurt)",
        is_eu_compliant=True,
        data_processing_agreement=True,
        certifications=frozenset({"ISO-27001", "GDPR-DPA"}),
    ),
    "us": EndpointMetadata(
        provider_id="external-llm-us",
        region="us-east-1 (Virginia)",
        is_eu_compliant=False,
        data_processing_agreement=False,
    ),
}


def build_demo_pipeline(
    *,
    data_class: DataClass,
    audit_writer: DemoAuditWriter,
    use_ner: bool = False,
    mask_pesel: bool = False,
) -> Pipeline:
    """Buduje niemutowalny Inbound Pipeline przez PipelineBuilder."""
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        HeuristicPIIDetector(),
    ]
    if use_ner:
        detectors.extend(
            [
                EnglishTransformerNERDetector(),
                PolishTransformerNERDetector(),
            ]
        )

    builder = (
        PipelineBuilder()
        .for_data_class(data_class)
        .with_audit_level(AuditLevel.FULL)
        .with_detectors(detectors)
        .with_context_enhancer(ContextRuleEnhancer())
        .with_anonymization_strategy(TokenizationStrategy(reversible=False))
        .with_residency_policy(DemoResidencyPolicyEngine())
        .with_pdf_extraction_policy(PDFExtractionPolicy.STRICT_NO_OCR)
        .with_audit_writer(audit_writer)
    )
    if mask_pesel:
        builder = builder.with_anonymization_strategy(
            EntityType.PESEL,
            MaskingStrategy(mask_char="*", preserve_length=True),
        )
    return builder.build()


def _load_pdf_attachment(pdf_path: Path) -> DocumentAttachment:
    if not pdf_path.exists() or not pdf_path.is_file():
        raise FileNotFoundError(f"Nie znaleziono pliku PDF: {pdf_path}")
    return DocumentAttachment(
        filename=pdf_path.name,
        content_bytes=pdf_path.read_bytes(),
        mime_type="application/pdf",
    )


def _render_stage_details(
    stage_name: str,
    prev_ctx: PipelineContext,
    next_ctx: PipelineContext,
    elapsed_ms: float,
    audit_writer: DemoAuditWriter,
    prev_audit_count: int,
) -> None:
    """Wyświetla czytelny opis tego, co zmienił pojedynczy filtr w PipelineContext."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Pole", style="bold cyan", width=26)
    table.add_column("Wartość")

    if stage_name == "DocumentExtractorFilter":
        if not prev_ctx.attachments:
            table.add_row("Tryb", "Pass-through (brak załącznika PDF)")
        else:
            names = ", ".join(a.filename for a in prev_ctx.attachments)
            total_bytes = sum(len(a.content_bytes) for a in prev_ctx.attachments)
            table.add_row("Przetworzony PDF", f"{names} ({total_bytes} B)")
            table.add_row(
                "Metadane XMP /Info",
                "Usunięte lokalnie (Extract-Then-Anonymize, ADR-009)",
            )
            table.add_row(
                "Załączniki po filtrze",
                f"{len(next_ctx.attachments)} (surowe binaria usunięte z kontekstu)",
            )
            table.add_row(
                "Wyciągnięty tekst",
                next_ctx.raw_text[:300] + ("..." if len(next_ctx.raw_text) > 300 else ""),
            )

    elif stage_name == "LanguageDetectorFilter":
        table.add_row("Wykryty język", f"[bold green]{next_ctx.language.upper()}[/bold green]")

    elif stage_name == "PIIDetectorFilter":
        table.add_row("Klasa danych", f"[bold]{next_ctx.data_class.value}[/bold]")
        table.add_row("Liczba encji", str(len(next_ctx.detected_entities)))
        if next_ctx.detected_entities:
            ent_lines = [
                (
                    f"• {e.entity_type.value:<12} | span=({e.start},{e.end}) | "
                    f"len={len(e.raw_value)} | conf={e.confidence:.2f} | "
                    f"det={e.detector_id}"
                )
                for e in next_ctx.detected_entities
            ]
            table.add_row("Wykryte encje (bez PII)", "\n".join(ent_lines))
        else:
            if next_ctx.tool_call is not None and not next_ctx.current_text.strip():
                table.add_row(
                    "Tryb ToolCall",
                    "Argumenty JSON zostaną przeskanowane rekurencyjnie w AnonymizationFilter",
                )
            else:
                table.add_row("Wykryte encje", "Brak wykrytych danych wrażliwych")

    elif stage_name == "AnonymizationFilter":
        if next_ctx.anonymization_results:
            rep_lines = [
                f"• {r.entity_type.value:<12} -> [bold yellow]{r.replacement_text}[/bold yellow] "
                f"(reversible={r.is_reversible})"
                for r in next_ctx.anonymization_results
            ]
            table.add_row("Zastosowane zamiany", "\n".join(rep_lines))
        else:
            table.add_row("Zastosowane zamiany", "Brak (tekst bez zmian)")
        if next_ctx.tool_call is not None:
            table.add_row(
                "Zanonimizowany ToolCall",
                json.dumps(next_ctx.tool_call.arguments, ensure_ascii=False),
            )
        else:
            table.add_row("Tekst po anonimizacji", next_ctx.sanitized_text)

    elif stage_name == "ResidencyPolicyFilter":
        ep = next_ctx.target_endpoint
        if ep is None:
            table.add_row("Decyzja", "Pominięto (brak target_endpoint)")
        else:
            table.add_row("Docelowy LLM", f"{ep.provider_id} @ {ep.region}")
            table.add_row("EU Compliant", str(ep.is_eu_compliant))
            table.add_row("Decyzja", "[bold green]ALLOWED[/bold green] (zgodne z polityką)")

    elif stage_name == "AuditContextFilter":
        new_events = audit_writer.events()[prev_audit_count:]
        if new_events:
            evt = new_events[-1]
            table.add_row("Zdarzenie audytowe", f"{evt.action.value} -> {evt.outcome.value}")
            table.add_row("Powód (zero PII)", evt.reason or "-")
            table.add_row("Event ID", evt.event_id)
        else:
            table.add_row("Audyt", "Brak nowego wpisu")

    console.print(
        Panel(
            table,
            title=f"[bold white]{stage_name}[/bold white] [dim]({elapsed_ms:.2f} ms)[/dim]",
            border_style="blue",
        )
    )


def run_trace(
    *,
    prompt_text: str,
    pdf_path: Path | None,
    endpoint_key: str,
    data_class: DataClass,
    tool_call: ToolCall | None = None,
    use_ner: bool = False,
    mask_pesel: bool = False,
) -> int:
    """Uruchamia potok etap po etapie i wypisuje szczegółowy ślad wykonania."""
    audit_writer = DemoAuditWriter()
    pipeline = build_demo_pipeline(
        data_class=data_class,
        audit_writer=audit_writer,
        use_ner=use_ner,
        mask_pesel=mask_pesel,
    )

    attachments: tuple[DocumentAttachment, ...] = ()
    if pdf_path is not None:
        attachments = (_load_pdf_attachment(pdf_path),)

    endpoint = ENDPOINTS[endpoint_key]
    principal = SecurityPrincipal(
        principal_id="demo_user",
        tenant_id="tenant_pl_01",
        roles=frozenset({"USER"}),
    )

    ctx = PipelineContext(
        request_id=f"req_{uuid.uuid4().hex[:8]}",
        session_id=tool_call.session_id if tool_call is not None else "sess_demo_01",
        tenant_id="tenant_pl_01",
        raw_text=prompt_text,
        data_class=data_class,
        audit_level=AuditLevel.FULL,
        attachments=attachments,
        tool_call=tool_call,
        target_endpoint=endpoint,
        principal=principal,
    )

    header_lines = [
        f"[bold]Request ID:[/bold] {ctx.request_id}",
        f"[bold]Wejście tekstowe:[/bold] {prompt_text if prompt_text else '(brak)'}",
        f"[bold]Załącznik PDF:[/bold] {pdf_path.name if pdf_path else '(brak)'}",
        f"[bold]ToolCall:[/bold] {tool_call.name if tool_call else '(brak)'}",
        f"[bold]DataClass:[/bold] {data_class.value}  |  [bold]Cel LLM:[/bold] {endpoint.region}",
    ]
    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold cyan]1. WEJŚCIE DO PIPELINE PROXY[/bold cyan]",
            border_style="cyan",
        )
    )

    total_start = time.perf_counter()
    current = ctx

    for index, stage in enumerate(pipeline.filters, start=1):
        prev_audit_count = len(audit_writer.events())
        stage_start = time.perf_counter()
        try:
            next_ctx = stage.process(current)
            next_ctx = next_ctx.with_filter_record(stage.filter_name)
        except HardStopError as exc:
            elapsed_ms = (time.perf_counter() - stage_start) * 1000.0
            new_events = audit_writer.events()[prev_audit_count:]
            audit_info = (
                f"\n[bold]AuditEvent:[/bold] {new_events[-1].action.value} -> "
                f"{new_events[-1].outcome.value} ({new_events[-1].reason})"
                if new_events
                else ""
            )
            console.print(
                Panel(
                    f"[bold red]ZATRZYMANO POTOK (FAIL-CLOSED SHORT-CIRCUITING)[/bold red]\n"
                    f"[bold]Filtr blokujący:[/bold] {stage.filter_name} (etap {index})\n"
                    f"[bold]Wyjątek:[/bold] {type(exc).__name__}: {exc}{audit_info}\n\n"
                    f"[dim]Pozostałe filtry nie zostały uruchomione. "
                    f"Nic nie zostało wysłane do zewnętrznego LLM.[/dim]",
                    title=f"[bold red]HARD STOP ({elapsed_ms:.2f} ms)[/bold red]",
                    border_style="red",
                )
            )
            return 2

        elapsed_ms = (time.perf_counter() - stage_start) * 1000.0
        _render_stage_details(
            stage.filter_name,
            current,
            next_ctx,
            elapsed_ms,
            audit_writer,
            prev_audit_count,
        )
        current = next_ctx

    total_ms = (time.perf_counter() - total_start) * 1000.0

    if current.tool_call is not None:
        outbound_payload = json.dumps(
            {
                "id": current.tool_call.id,
                "name": current.tool_call.name,
                "arguments": current.tool_call.arguments,
                "session_id": current.tool_call.session_id,
            },
            ensure_ascii=False,
            indent=2,
        )
    else:
        outbound_payload = current.sanitized_text

    applied = " -> ".join(f.filter_name for f in current.applied_filters)
    summary_text = Text()
    summary_text.append("Tekst / JSON wysyłany do zewnętrznego LLM:\n", style="bold green")
    summary_text.append(f"{outbound_payload}\n\n", style="bold yellow")
    summary_text.append(f"Załączniki binarne wysyłane do LLM: {len(current.attachments)}\n")
    summary_text.append(f"Wykonane filtry: {applied}\n", style="dim")
    summary_text.append(f"Całkowity czas Inbound Pipeline: {total_ms:.2f} ms", style="dim")

    console.print(
        Panel(
            summary_text,
            title="[bold green]2. WYNIK GOTOWY DO WYSŁANIA DO ZEWNĘTRZNEGO LLM[/bold green]",
            border_style="green",
        )
    )
    return 0


def _interactive_loop(use_ner: bool) -> int:
    text_pdf, scan_pdf = ensure_sample_pdfs()

    console.print(
        Panel(
            "[bold]Prezentacja Inbound Pipeline (Osoba A)[/bold]\n"
            "Wpisz własny prompt lub wybierz gotowy PDF / ToolCall, aby zobaczyć "
            "krok po kroku, co dzieje się z danymi przed wysyłką do LLM.",
            border_style="magenta",
        )
    )

    while True:
        console.print("\n[bold magenta]Wybierz tryb testu:[/bold magenta]")
        console.print("  \\[1] Wpisz własny prompt tekstowy")
        console.print("  \\[2] Wpisz prompt + podaj ścieżkę do własnego pliku PDF")
        console.print(f"  \\[3] Demo PDF tekstowy z ukrytymi metadanymi ({text_pdf.name})")
        console.print(f"  \\[4] Demo PDF skan bez OCR — blokada FAIL-CLOSED ({scan_pdf.name})")
        console.print("  \\[5] Demo ToolCall JSON (rekurencyjna anonimizacja argumentów)")
        console.print("  \\[q] Wyjście")

        choice = Prompt.ask("Wybór", choices=["1", "2", "3", "4", "5", "q"], default="1")
        if choice == "q":
            return 0

        prompt_text = ""
        pdf_path: Path | None = None
        tool_call: ToolCall | None = None

        if choice == "1":
            prompt_text = Prompt.ask(
                "Wpisz prompt",
                default="Pacjent Jan Kowalski, PESEL 44051401458, mieszka przy ul. Lipowej 5.",
            )
        elif choice == "2":
            prompt_text = Prompt.ask("Opcjonalny prompt tekstowy (Enter jeśli sam PDF)", default="")
            raw_path = Prompt.ask("Ścieżka do pliku PDF", default=str(text_pdf))
            pdf_path = Path(raw_path).expanduser()
        elif choice == "3":
            prompt_text = Prompt.ask(
                "Opcjonalny prompt do załącznika",
                default="Przeanalizuj załączoną fakturę.",
            )
            pdf_path = text_pdf
        elif choice == "4":
            pdf_path = scan_pdf
        elif choice == "5":
            raw_name = Prompt.ask("Imię i nazwisko w argumencie ToolCall", default="Jan Kowalski")
            raw_pesel = Prompt.ask("PESEL w argumencie ToolCall", default="44051401458")
            tool_call = ToolCall(
                id="call_demo_01",
                name="pobierz_historie_pacjenta",
                arguments={
                    "pacjent": raw_name,
                    "dane": {"pesel": raw_pesel, "limit_rekordow": 5},
                },
                session_id="sess_demo_01",
            )

        data_class_str = Prompt.ask(
            "Klasa danych (GENERAL / FINANCIAL / MEDICAL)",
            choices=["GENERAL", "FINANCIAL", "MEDICAL"],
            default="GENERAL",
        )
        endpoint_key = Prompt.ask(
            "Docelowy region LLM (eu = eu-central-1, us = us-east-1)",
            choices=["eu", "us"],
            default="eu",
        )
        mask_pesel_ans = Prompt.ask(
            "Maskować PESEL gwiazdkami zamiast tokena <PESEL_1>? (t/n)",
            choices=["t", "n"],
            default="n",
        )

        try:
            run_trace(
                prompt_text=prompt_text,
                pdf_path=pdf_path,
                endpoint_key=endpoint_key,
                data_class=DataClass(data_class_str),
                tool_call=tool_call,
                use_ner=use_ner,
                mask_pesel=(mask_pesel_ans == "t"),
            )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[bold red]Błąd wejścia:[/bold red] {exc}")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prezentacja CLI Inbound Pipeline (Osoba A): tekst, PDF i ToolCall."
    )
    parser.add_argument("--prompt", type=str, default=None, help="Tekst promptu do analizy.")
    parser.add_argument("--pdf", type=Path, default=None, help="Ścieżka do pliku PDF.")
    parser.add_argument(
        "--endpoint",
        choices=["eu", "us"],
        default="eu",
        help="Docelowy region LLM (domyślnie: eu).",
    )
    parser.add_argument(
        "--data-class",
        choices=[dc.value for dc in DataClass],
        default=DataClass.GENERAL.value,
        help="Klasa wrażliwości danych.",
    )
    parser.add_argument(
        "--mask-pesel",
        action="store_true",
        help="Użyj MaskingStrategy (***) zamiast TokenizationStrategy dla PESEL.",
    )
    parser.add_argument(
        "--ner",
        action="store_true",
        help="Dołącz Transformer NER (wymaga pobranych wag HuggingFace).",
    )
    parser.add_argument(
        "--tool-call-json",
        type=str,
        default=None,
        help="JSON z argumentami ToolCall do rekurencyjnej anonimizacji.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    ensure_sample_pdfs()

    if args.prompt is None and args.pdf is None and args.tool_call_json is None:
        return _interactive_loop(use_ner=args.ner)

    tool_call: ToolCall | None = None
    if args.tool_call_json is not None:
        parsed_args: dict[str, Any] = json.loads(args.tool_call_json)
        tool_call = ToolCall(
            id="call_cli_01",
            name="demo_tool",
            arguments=parsed_args,
            session_id="sess_cli_01",
        )

    return run_trace(
        prompt_text=args.prompt or "",
        pdf_path=args.pdf,
        endpoint_key=args.endpoint,
        data_class=DataClass(args.data_class),
        tool_call=tool_call,
        use_ner=args.ner,
        mask_pesel=args.mask_pesel,
    )


if __name__ == "__main__":
    raise SystemExit(main())

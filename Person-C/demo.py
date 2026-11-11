"""Skrypt demonstracyjny (CLI Demo) dla komponentów Osoby C.

Uruchomienie:
    $env:PYTHONPATH="src"
    python Person-C/demo.py

Pokazuje krok po kroku:
1. Scenariusz PL: Detekcja PHI + QID -> Ryzyko k-anonimowości (GUS) -> Generalizacja taksonomiczna (ISCO/TERYT)
2. Scenariusz EN: Detekcja PHI + QID -> Ryzyko k-anonimowości (US Census) -> Generalizacja taksonomiczna (ISCO/GeoNames)
3. Scenariusz ADR-005: Analiza l-różnorodności i t-bliskości (atak homogeniczności vs kohorta bezpieczna)
4. Wzorzec Strategy: StrategySelector dobierający GeneralizationStrategy i MaskingStrategy
"""

from __future__ import annotations

import sys
from pathlib import Path

# Dodajemy katalog 'src' do sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from detectors.phi_detector import PHIDetector
from detectors.qid_detector import QIDDetector
from domain.models import (
    AnonymizationRequest,
    DataClass,
    EntityCategory,
    EntityType,
    Language,
)
from pipeline.context import PipelineContext
from pipeline.reid_risk_analyzer import DataClassifierFilter, ReIdRiskAnalyzer
from strategies.generalization import GeneralizationStrategy
from strategies.masking import MaskingStrategy
from strategies.selector import StrategySelector


def separator(title: str) -> None:
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def run_demo() -> None:
    phi_det = PHIDetector()
    qid_det = QIDDetector()
    classifier = DataClassifierFilter()
    analyzer = ReIdRiskAnalyzer(k_min=5, l_threshold=3, t_threshold=0.30)
    gen_strat = GeneralizationStrategy()
    mask_strat = MaskingStrategy(preserve_length=True)
    selector = StrategySelector(
        generalization_strategy=gen_strat,
        masking_strategy=mask_strat,
    )

    # -------------------------------------------------------------------------
    # 1. SCENARIUSZ POLSKI (PL)
    # -------------------------------------------------------------------------
    separator("1. SCENARIUSZ POLSKI (PL): Pacjent, lat 47, neurochirurg z Sępólna")
    prompt_pl = (
        "Pacjent Jan Kowalski, lat 47, zawód: neurochirurg, "
        "zamieszkały w Sępólnie Krajeńskim. Rozpoznanie ICD-10: C71.9 (rzadki guz mózgu). "
        "Zalecono: Metformina 850 mg."
    )
    print(f"[TEKST WEJŚCIOWY]\n  \"{prompt_pl}\"")

    # Krok 1: Detekcja PHI i QID
    phi_pl = phi_det.detect(prompt_pl, Language.PL)
    qid_pl = qid_det.detect(prompt_pl, Language.PL)
    all_entities_pl = sorted(list(phi_pl) + list(qid_pl), key=lambda e: e.start)

    print("\n[KROK 1: WYKRYTE ENCYJE PHI / QID]")
    for e in all_entities_pl:
        cat_tag = "PHI" if e.category == EntityCategory.PHI else "QID"
        print(f"  * [{cat_tag}] {e.entity_type.value:18s} -> '{e.value}' (canonical: {e.canonical_id})")

    # Krok 2: Klasyfikacja klasy danych
    ctx_pl = PipelineContext(
        request_id="req-demo-pl",
        tenant_id="hospital-pl",
        text=prompt_pl,
        language=Language.PL,
        data_class=DataClass.GENERAL,
        entities=tuple(all_entities_pl),
    )
    ctx_pl = classifier.process(ctx_pl)
    print(f"\n[KROK 2: KLASYFIKACJA DANYCH] data_class = {ctx_pl.data_class.value} (Flaga MEDICAL dla Osoby B)")

    # Krok 3: Analiza k-anonimowości (GUS)
    report_pl = analyzer.analyze(all_entities_pl, Language.PL)
    print("\n[KROK 3: OCENA RYZYKA RE-IDENTYFIKACJI]")
    print(f"  - Populacja referencyjna (GUS):       {report_pl.population:,} osób".replace(",", " "))
    print(f"  - Liczba wykrytych Quasi-ID:          {report_pl.qid_count}")
    print(f"  - Szacowane początkowe k̂:              {report_pl.k_estimate:.6f} osób (< 5.0 -> KRYTYCZNE RYZYKO!)")
    print(f"  - Wskaźnik unikalności (Uniqueness):  {report_pl.uniqueness_score * 100:.1f}%")
    print(f"  - Decyzja algorytmu:                  {report_pl.decision.value}")

    print("\n[KROK 4: ADAPTACYJNE UOGÓLNIANIE W DRZEWIE TAKSONOMICZNYM]")
    for step in report_pl.steps:
        ent = next(e for e in all_entities_pl if step.matches(e))
        gen_val = gen_strat.anonymize(
            ent,
            AnonymizationRequest(
                request_id=ctx_pl.request_id,
                language=Language.PL,
                data_class=ctx_pl.data_class,
                generalization_level=step.level,
            ),
        ).replacement
        print(
            f"  * {step.dimension_id:12s}: '{ent.value}' "
            f"--[+{step.level} poziomów w drzewie]--> '{gen_val}' "
            f"(P(Q_i): {step.probability_before:.6f} -> {step.probability_after:.6f})"
        )
    print(f"  => Nowe k̂ po minimalnej generalizacji: {report_pl.k_after:.2f} osób (Bezpieczne, k̂ >= 5.0!)")

    # Krok 5: Transformacja tekstu przez StrategySelector
    transformed_pl = prompt_pl
    # Zastępujemy od końca tekstu, aby offsety pozostały poprawne
    for e in sorted(all_entities_pl, key=lambda x: x.start, reverse=True):
        strat, adj_req = selector.select(
            e,
            AnonymizationRequest(
                request_id=ctx_pl.request_id,
                language=Language.PL,
                data_class=ctx_pl.data_class,
            ),
            risk_assessment=report_pl,
        )
        anonymized = strat.anonymize(e, adj_req)
        transformed_pl = transformed_pl[:e.start] + anonymized.replacement + transformed_pl[e.end:]

    print(f"\n[KROK 5: WYNIKOWY PROMPT DLA LLM (PL)]\n  \"{transformed_pl}\"")

    # -------------------------------------------------------------------------
    # 2. SCENARIUSZ ANGIELSKI (EN)
    # -------------------------------------------------------------------------
    separator("2. SCENARIUSZ ANGIELSKI (EN): 47-year-old neurosurgeon in Cambridge")
    prompt_en = (
        "Patient is a 47-year-old neurosurgeon residing in Cambridge, "
        "diagnosed with glioblastoma (ICD-10: C71), prescribed Lipitor 20 mg."
    )
    print(f"[TEKST WEJŚCIOWY]\n  \"{prompt_en}\"")

    phi_en = phi_det.detect(prompt_en, Language.EN)
    qid_en = qid_det.detect(prompt_en, Language.EN)
    all_entities_en = sorted(list(phi_en) + list(qid_en), key=lambda e: e.start)

    print("\n[KROK 1: WYKRYTE ENCYJE PHI / QID]")
    for e in all_entities_en:
        cat_tag = "PHI" if e.category == EntityCategory.PHI else "QID"
        print(f"  * [{cat_tag}] {e.entity_type.value:18s} -> '{e.value}' (canonical: {e.canonical_id})")

    report_en = analyzer.analyze(all_entities_en, Language.EN)
    print("\n[KROK 2: OCENA RYZYKA RE-IDENTYFIKACJI (US CENSUS)]")
    print(f"  - Populacja referencyjna (US):        {report_en.population:,} osób".replace(",", " "))
    print(f"  - Szacowane początkowe k̂:              {report_en.k_estimate:.6f} osób (< 5.0 -> RYZYKO!)")
    print(f"  - Decyzja algorytmu:                  {report_en.decision.value}")

    print("\n[KROK 3: UOGÓLNIANIE Z ZACHOWANIEM JĘZYKA ANGIELSKIEGO]")
    for step in report_en.steps:
        ent = next(e for e in all_entities_en if step.matches(e))
        gen_val = gen_strat.anonymize(
            ent,
            AnonymizationRequest(
                request_id="req-en",
                language=Language.EN,
                data_class=DataClass.MEDICAL,
                generalization_level=step.level,
            ),
        ).replacement
        print(f"  * {step.dimension_id:12s}: '{ent.value}' --[+{step.level} steps]--> '{gen_val}'")
    print(f"  => Nowe k̂ po generalizacji:            {report_en.k_after:.2f} osób (k̂ >= 5.0!)")

    transformed_en = prompt_en
    for e in sorted(all_entities_en, key=lambda x: x.start, reverse=True):
        strat, adj_req = selector.select(
            e,
            AnonymizationRequest(
                request_id="req-en",
                language=Language.EN,
                data_class=DataClass.MEDICAL,
            ),
            risk_assessment=report_en,
        )
        anonymized = strat.anonymize(e, adj_req)
        transformed_en = transformed_en[:e.start] + anonymized.replacement + transformed_en[e.end:]

    print(f"\n[KROK 4: WYNIKOWY PROMPT DLA LLM (EN)]\n  \"{transformed_en}\"")

    # -------------------------------------------------------------------------
    # 3. SCENARIUSZ ADR-005 (l-różnorodność i t-bliskość)
    # -------------------------------------------------------------------------
    separator("3. SCENARIUSZ ADR-005: Atak Homogeniczności vs Kohorta Zróżnicowana")
    # Kohorta 1: 5 pacjentów, wszyscy z tą samą chorobą (ONCOLOGY)
    cohort_homo = ["ONCOLOGY", "ONCOLOGY", "ONCOLOGY", "ONCOLOGY", "ONCOLOGY"]
    eval_homo = analyzer._evaluate_sensitive([], cohort_homo)

    # Kohorta 2: 5 pacjentów z różnymi chorobami
    cohort_div = ["CARDIOLOGY", "CARDIOLOGY", "ENDOCRINOLOGY", "PULMONOLOGY", "NEUROLOGY"]
    eval_div = analyzer._evaluate_sensitive([], cohort_div)

    print("Kohorta A (Jednorodna - 5x ONCOLOGY):")
    print(f"  * Distinct l:  {eval_homo.distinct_l} (wymóg >= {eval_homo.l_threshold}) -> Spełnia: {eval_homo.is_l_diverse}")
    print(f"  * t-closeness: {eval_homo.t_closeness} (wymóg <= {eval_homo.t_threshold}) -> Spełnia: {eval_homo.is_t_close} [ALARM: ATAK HOMOGENICZNOŚCI!]")

    print("\nKohorta B (Zróżnicowana):")
    print(f"  * Distinct l:  {eval_div.distinct_l} (wymóg >= {eval_div.l_threshold}) -> Spełnia: {eval_div.is_l_diverse}")
    print(f"  * t-closeness: {eval_div.t_closeness} (wymóg <= {eval_div.t_threshold}) -> Spełnia: {eval_div.is_t_close} [BEZPIECZNA]")


if __name__ == "__main__":
    run_demo()


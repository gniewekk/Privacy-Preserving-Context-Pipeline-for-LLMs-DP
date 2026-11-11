"""Detektor Danych Medycznych (PHI - Protected Health Information).

Obsługuje język polski (PL) i angielski (EN):
1. Kody jednostek chorobowych: ICD-10 (C71, I10, E11.9) oraz procedury ICD-9.
2. Opisy chorób: Słowniki pojęć medycznych PL (CeZ/NFZ) i EN (WHO/CDC).
3. Leki i substancje: Nazwy międzynarodowe INN oraz handlowe (RPL / RxNorm).
4. Dawkowanie i wyniki laboratoryjne (dwujęzyczne regexy).
5. Zasoby ustrukturyzowane: HL7 v2 (DG1, OBX) oraz HL7 FHIR (Condition, Observation, MedicationRequest).
6. Reguły kontekstowe (Context Enhancers) dla rozpoznań i hospitalizacji.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

from domain.models import DetectedEntity, EntityCategory, EntityType, Language
from resources.taxonomies.icd10 import ICD10Taxonomy, MEDICATIONS, MEDICAL_TERMS


class PHIDetector:
    """Wielojęzyczny detektor danych medycznych PHI."""

    detector_id: str = "phi_detector_multilingual"

    # 1. Kody ICD-10: np. C71, C71.9, I10, E11.9, F32.1
    _ICD10_PATTERN = re.compile(
        r"(?<![A-Z0-9])([A-TV-Z]\d{2}(?:\.\d{1,2})?)(?![A-Z0-9])"
    )

    # 2. Kody procedur ICD-9: np. "ICD-9: 88.72", "procedure 99.25"
    _ICD9_PATTERN = re.compile(
        r"(?i)\b(?:icd-?9|procedur[aęy]|procedure)\s*[:#-]?\s*(\d{2}\.\d{1,2})\b"
    )

    # 3. Dawkowanie: nie może łapać jednostek stężenia (/dl, /l, /ml, /kg)
    _DOSAGE_PATTERN = re.compile(
        r"(?i)\b(\d+(?:[.,]\d+)?\s*(?:mg|mcg|ug|g|ml|j\.?m\.?|units?)"
        r"(?!\s*/\s*(?:dl|l|ml|kg|ul|mmol))"
        r"(?:\s*(?:na\s+dobę|dziennie|raz\s+dziennie|daily|once\s+daily|twice\s+daily|b\.?i\.?d\.?|t\.?i\.?d\.?|q\.?d\.?))?)\b"
    )

    # 4. Wyniki badań laboratoryjnych: dwujęzyczne
    _LAB_PATTERN = re.compile(
        r"(?i)\b((?:hba1c|glukoz[a-z]*(?:\s+na\s+czczo)?|fasting\s+glucose|glucose|kreatynin[a-z]*|creatinine|tsh|crp|hemoglobin[a-z]*|wbc|plt|inr|alt|ast|cholesterol)"
        r"\s*[:=]?\s*\d+(?:[.,]\d+)?\s*(?:%|mg/dl|mmol/l|u/l|g/dl|mln/ul|tys/ul|miu/l))"
    )

    # 5. Kontekstowe reguły rozpoznań (Context Enhancers)
    _CONTEXT_DIAGNOSIS_PL = re.compile(
        r"(?i)\b(?:diagnoz[a-z]*|rozpoznan[a-z]*|stwierdzon[a-z]*|podejrzen[a-z]*)\s*[:#-]?\s*([^,\n.;]+)"
    )
    _CONTEXT_DIAGNOSIS_EN = re.compile(
        r"(?i)\b(?:diagnos(?:ed\s+with|is)|condition|impression|assessment)\s*[:#-]?\s*([^,\n.;]+)"
    )

    # 6. Kontekstowe reguły hospitalizacji
    _CONTEXT_HOSPITAL_PL = re.compile(
        r"(?i)\b(?:hospitalizacj[a-z]*|przyjęty\s+na\s+oddział|oddział)\s*[:#-]?\s*([^,\n.;]+)"
    )
    _CONTEXT_HOSPITAL_EN = re.compile(
        r"(?i)\b(?:hospitaliz(?:ed\s+at|ation)|admitted\s+to|department\s+of)\s*[:#-]?\s*([^,\n.;]+)"
    )

    # 7. HL7 v2 segmenty
    _HL7_DG1 = re.compile(r"DG1\|\d+\|[^|]*\|([^|\r\n]+)")
    _HL7_OBX = re.compile(r"OBX\|\d+\|[A-Z]{2}\|([^|\r\n]+\|[^|\r\n]*\|[^|\r\n]+)")

    def detect(self, text: str, language: Language | str) -> Sequence[DetectedEntity]:
        lang = Language(language) if isinstance(language, str) else language
        entities: list[DetectedEntity] = []

        # A. Ustrukturyzowane formaty: HL7 FHIR (JSON)
        fhir_entities = self._detect_fhir(text)
        entities.extend(fhir_entities)

        # B. Ustrukturyzowane formaty: HL7 v2 (DG1, OBX)
        for match in self._HL7_DG1.finditer(text):
            val = match.group(1).strip()
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.MEDICAL_CONDITION,
                    category=EntityCategory.PHI,
                    start=match.start(1),
                    end=match.end(1),
                    value=val,
                    confidence=0.98,
                    detector_id=self.detector_id,
                    canonical_id="HL7-DG1",
                )
            )
        for match in self._HL7_OBX.finditer(text):
            val = match.group(1).strip()
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.LAB_RESULT,
                    category=EntityCategory.PHI,
                    start=match.start(1),
                    end=match.end(1),
                    value=val,
                    confidence=0.98,
                    detector_id=self.detector_id,
                    canonical_id="HL7-OBX",
                )
            )

        # C. Kody ICD-10
        for match in self._ICD10_PATTERN.finditer(text):
            code_candidate = match.group(1)
            entry = ICD10Taxonomy.lookup_code(code_candidate)
            context_window = text[max(0, match.start() - 30) : min(len(text), match.end() + 30)].lower()
            if entry is not None or "icd" in context_window or "diagno" in context_window:
                entities.append(
                    DetectedEntity(
                        entity_type=EntityType.ICD10_CODE,
                        category=EntityCategory.PHI,
                        start=match.start(1),
                        end=match.end(1),
                        value=code_candidate,
                        confidence=0.99 if entry else 0.85,
                        detector_id=self.detector_id,
                        canonical_id=entry.code if entry else code_candidate[:3].upper(),
                    )
                )

        # D. Kody procedur ICD-9
        for match in self._ICD9_PATTERN.finditer(text):
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.ICD9_PROCEDURE,
                    category=EntityCategory.PHI,
                    start=match.start(1),
                    end=match.end(1),
                    value=match.group(1),
                    confidence=0.95,
                    detector_id=self.detector_id,
                    canonical_id=f"ICD9:{match.group(1)}",
                )
            )

        # E. Wyniki laboratoryjne (wyższy priorytet przed ogólnym dawkowaniem)
        for match in self._LAB_PATTERN.finditer(text):
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.LAB_RESULT,
                    category=EntityCategory.PHI,
                    start=match.start(1),
                    end=match.end(1),
                    value=match.group(1),
                    confidence=0.95,
                    detector_id=self.detector_id,
                )
            )

        # F. Słownikowe pojęcia medyczne (PL i EN)
        text_lower = text.lower()
        for term, (cat, code) in sorted(MEDICAL_TERMS.items(), key=lambda x: len(x[0]), reverse=True):
            start = 0
            while True:
                idx = text_lower.find(term, start)
                if idx == -1:
                    break
                before_ok = (idx == 0 or not text_lower[idx - 1].isalnum())
                after_idx = idx + len(term)
                after_ok = (after_idx == len(text_lower) or not text_lower[after_idx].isalnum())
                if before_ok and after_ok:
                    entities.append(
                        DetectedEntity(
                            entity_type=EntityType.MEDICAL_CONDITION,
                            category=EntityCategory.PHI,
                            start=idx,
                            end=after_idx,
                            value=text[idx:after_idx],
                            confidence=0.92,
                            detector_id=self.detector_id,
                            canonical_id=code,
                        )
                    )
                start = after_idx

        # G. Leki (INN, RPL, RxNorm)
        for med in sorted(MEDICATIONS, key=len, reverse=True):
            pattern = re.compile(rf"(?<![\wąćęłńóśźż])({re.escape(med)})(?![\wąćęłńóśźż])", re.IGNORECASE)
            for m in pattern.finditer(text):
                entities.append(
                    DetectedEntity(
                        entity_type=EntityType.MEDICATION,
                        category=EntityCategory.PHI,
                        start=m.start(1),
                        end=m.end(1),
                        value=m.group(1),
                        confidence=0.90,
                        detector_id=self.detector_id,
                        canonical_id=f"MED:{med.upper()}",
                    )
                )

        # H. Dawkowanie
        for match in self._DOSAGE_PATTERN.finditer(text):
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.DOSAGE,
                    category=EntityCategory.PHI,
                    start=match.start(1),
                    end=match.end(1),
                    value=match.group(1),
                    confidence=0.88,
                    detector_id=self.detector_id,
                )
            )

        # I. Reguły kontekstowe (Context Enhancers)
        diag_regex = self._CONTEXT_DIAGNOSIS_PL if lang == Language.PL else self._CONTEXT_DIAGNOSIS_EN
        for match in diag_regex.finditer(text):
            val = match.group(1).strip()
            # Nie dopasowuj, jeśli tekst zawiera już zidentyfikowany kod ICD-10
            if len(val) >= 3 and not re.search(r"[A-TV-Z]\d{2}", val):
                entities.append(
                    DetectedEntity(
                        entity_type=EntityType.MEDICAL_CONDITION,
                        category=EntityCategory.PHI,
                        start=match.start(1),
                        end=match.end(1),
                        value=val,
                        confidence=0.75,
                        detector_id=self.detector_id,
                    )
                )

        hosp_regex = self._CONTEXT_HOSPITAL_PL if lang == Language.PL else self._CONTEXT_HOSPITAL_EN
        for match in hosp_regex.finditer(text):
            val = match.group(1).strip()
            if len(val) >= 3:
                entities.append(
                    DetectedEntity(
                        entity_type=EntityType.HOSPITALIZATION,
                        category=EntityCategory.PHI,
                        start=match.start(1),
                        end=match.end(1),
                        value=val,
                        confidence=0.82,
                        detector_id=self.detector_id,
                    )
                )

        return self._resolve_overlaps(entities)

    def _detect_fhir(self, text: str) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        trimmed = text.strip()
        if not (trimmed.startswith("{") and trimmed.endswith("}")):
            return entities

        try:
            data = json.loads(trimmed)
        except Exception:
            return entities

        if not isinstance(data, dict):
            return entities

        res_type = data.get("resourceType")
        if res_type == "Condition":
            code_obj = data.get("code", {})
            for coding in code_obj.get("coding", []):
                code = coding.get("code")
                if code:
                    idx = text.find(code)
                    if idx != -1:
                        entities.append(
                            DetectedEntity(
                                entity_type=EntityType.ICD10_CODE,
                                category=EntityCategory.PHI,
                                start=idx,
                                end=idx + len(code),
                                value=code,
                                confidence=1.0,
                                detector_id=self.detector_id,
                                canonical_id=code[:3].upper(),
                            )
                        )
        elif res_type == "Observation":
            code_obj = data.get("code", {})
            for coding in code_obj.get("coding", []):
                code = coding.get("code")
                if code:
                    idx = text.find(code)
                    if idx != -1:
                        entities.append(
                            DetectedEntity(
                                entity_type=EntityType.LAB_RESULT,
                                category=EntityCategory.PHI,
                                start=idx,
                                end=idx + len(code),
                                value=code,
                                confidence=1.0,
                                detector_id=self.detector_id,
                            )
                        )
        elif res_type == "MedicationRequest":
            med_obj = data.get("medicationCodeableConcept", {})
            for coding in med_obj.get("coding", []):
                display = coding.get("display")
                if display:
                    idx = text.find(display)
                    if idx != -1:
                        entities.append(
                            DetectedEntity(
                                entity_type=EntityType.MEDICATION,
                                category=EntityCategory.PHI,
                                start=idx,
                                end=idx + len(display),
                                value=display,
                                confidence=1.0,
                                detector_id=self.detector_id,
                            )
                        )
        return entities

    @staticmethod
    def _resolve_overlaps(entities: list[DetectedEntity]) -> list[DetectedEntity]:
        if not entities:
            return []

        # Wagi priorytetów typów encji przy nakładaniu
        type_priority = {
            EntityType.ICD10_CODE: 10,
            EntityType.ICD9_PROCEDURE: 10,
            EntityType.LAB_RESULT: 9,
            EntityType.MEDICATION: 8,
            EntityType.DOSAGE: 7,
            EntityType.MEDICAL_CONDITION: 5,
            EntityType.HOSPITALIZATION: 4,
        }

        sorted_entities = sorted(
            entities,
            key=lambda e: (
                e.start,
                -type_priority.get(e.entity_type, 0),
                -(e.end - e.start),
                -e.confidence,
            ),
        )
        result: list[DetectedEntity] = []
        for e in sorted_entities:
            if not any(e.overlaps(existing) for existing in result):
                result.append(e)
        return sorted(result, key=lambda e: (e.start, e.end))

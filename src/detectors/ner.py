"""Two Transformer NER detectors: English (dslim/bert-base-NER) and Polish (HerBERT NER)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from detectors.base import PIIDetector, register_detector, resolve_overlapping_spans
from domain.models import DataClass, DetectedEntity, EntityType

type RawNERPrediction = Mapping[str, Any]
type NERPipelineCallable = Callable[[str], Sequence[RawNERPrediction]]

DEFAULT_ENGLISH_NER_MODEL = "dslim/bert-base-NER"
DEFAULT_POLISH_NER_MODEL = "allegro/herbert-base-cased"
DEFAULT_POLISH_FINETUNED_NER_MODEL = "pietruszkowiec/herbert-base-ner"

# Unified label mapping covering CoNLL-2003 (English) and NKJP / KPWr (Polish) NER tagsets
_LABEL_TO_ENTITY_TYPE: Mapping[str, EntityType] = {
    # English CoNLL-2003 / OntoNotes tags
    "PER": EntityType.PERSON,
    "B-PER": EntityType.PERSON,
    "I-PER": EntityType.PERSON,
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORGANIZATION,
    "B-ORG": EntityType.ORGANIZATION,
    "I-ORG": EntityType.ORGANIZATION,
    "ORGANIZATION": EntityType.ORGANIZATION,
    "LOC": EntityType.LOCATION,
    "B-LOC": EntityType.LOCATION,
    "I-LOC": EntityType.LOCATION,
    "LOCATION": EntityType.LOCATION,
    "GPE": EntityType.LOCATION,
    "DATE": EntityType.DATE,
    "B-DATE": EntityType.DATE,
    "I-DATE": EntityType.DATE,
    # Polish NKJP / KPWr / PolBERT NER tags
    "PERSNAME": EntityType.PERSON,
    "NAM_LIV_PERSON": EntityType.PERSON,
    "B-NAM_LIV_PERSON": EntityType.PERSON,
    "I-NAM_LIV_PERSON": EntityType.PERSON,
    "PLACENAME": EntityType.LOCATION,
    "GEOGNAME": EntityType.LOCATION,
    "NAM_LOC": EntityType.LOCATION,
    "NAM_LOC_GPE_CITY": EntityType.LOCATION,
    "NAM_LOC_GPE_COUNTRY": EntityType.LOCATION,
    "NAM_FAC_ROAD": EntityType.LOCATION,
    "ORGNAME": EntityType.ORGANIZATION,
    "NAM_ORG": EntityType.ORGANIZATION,
    "NAM_ORG_INSTITUTION": EntityType.ORGANIZATION,
    "NAM_ORG_COMPANY": EntityType.ORGANIZATION,
}


@register_detector("ner")
class NERPIIDetector(PIIDetector):
    """Base Transformer NER strategy converting token-classification spans to DetectedEntity."""

    def __init__(
        self,
        model_name: str = DEFAULT_ENGLISH_NER_MODEL,
        ner_pipeline: NERPipelineCallable | None = None,
        min_confidence: float = 0.40,
        enable_lowercase_fallback: bool = True,
        target_language: str | None = None,
    ) -> None:
        self._model_name = model_name
        self._ner_pipeline = ner_pipeline
        self._min_confidence = min_confidence
        self._enable_lowercase_fallback = enable_lowercase_fallback
        self._target_language = target_language

    @property
    def detector_id(self) -> str:
        return f"transformer_ner:{self._model_name}"

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def target_language(self) -> str | None:
        return self._target_language

    def _get_or_create_pipeline(self) -> NERPipelineCallable:
        if self._ner_pipeline is not None:
            return self._ner_pipeline

        try:
            from transformers import pipeline as hf_pipeline  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "HuggingFace `transformers` and `torch` are required to load "
                f"{self._model_name!r}. Install optional dependencies via `pip install .[ner]` "
                "or inject a `ner_pipeline` callable."
            ) from exc

        hf_checkpoint = (
            DEFAULT_POLISH_FINETUNED_NER_MODEL
            if self._model_name == DEFAULT_POLISH_NER_MODEL
            else self._model_name
        )
        loaded_pipeline: Any = hf_pipeline(
            task="ner",
            model=hf_checkpoint,
            aggregation_strategy="simple",
        )
        self._ner_pipeline = loaded_pipeline
        return loaded_pipeline  # type: ignore[no-any-return]

    def _convert_predictions(
        self,
        original_text: str,
        predictions: Sequence[RawNERPrediction],
        confidence_penalty: float = 0.0,
    ) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        text_len = len(original_text)

        for pred in predictions:
            raw_label = str(pred.get("entity_group") or pred.get("entity") or "").upper()
            entity_type = _LABEL_TO_ENTITY_TYPE.get(raw_label)
            if entity_type is None:
                continue

            start_obj = pred.get("start")
            end_obj = pred.get("end")
            if not isinstance(start_obj, int) or not isinstance(end_obj, int):
                continue
            if start_obj < 0 or end_obj <= start_obj or end_obj > text_len:
                continue

            raw_score = float(pred.get("score", 0.85))
            adjusted_score = max(0.0, min(1.0, raw_score - confidence_penalty))
            if adjusted_score < self._min_confidence:
                continue

            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    start=start_obj,
                    end=end_obj,
                    raw_value=original_text[start_obj:end_obj],
                    confidence=adjusted_score,
                    data_class=DataClass.CONFIDENTIAL,
                    detector_id=self.detector_id,
                )
            )

        return entities

    def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
        """Run Transformer NER inference when `language` matches `target_language`."""
        if not text.strip():
            return ()
        if self._target_language is not None and language.lower() != self._target_language:
            return ()

        runner = self._get_or_create_pipeline()
        primary_predictions = runner(text)
        detected = self._convert_predictions(text, primary_predictions)

        # Level A Capitalization Bias Mitigation:
        # Cased BERT/HerBERT NER models often miss lowercase names embedded in mixed-case
        # or all-lowercase prompts (e.g., "Rozmawiałem z janem kowalskim w warszawie").
        # Project lowercase words to title-case of identical length and map offsets back.
        if self._enable_lowercase_fallback and any(c.islower() for c in text):
            title_projection = text.title()
            if title_projection != text and len(title_projection) == len(text):
                fallback_predictions = runner(title_projection)
                detected.extend(
                    self._convert_predictions(
                        text,
                        fallback_predictions,
                        confidence_penalty=0.10,
                    )
                )

        return resolve_overlapping_spans(detected)


@register_detector("ner_en")
class EnglishTransformerNERDetector(NERPIIDetector):
    """Dedicated English Transformer NER detector (`dslim/bert-base-NER`, CoNLL-2003 labels)."""

    def __init__(
        self,
        model_name: str = DEFAULT_ENGLISH_NER_MODEL,
        ner_pipeline: NERPipelineCallable | None = None,
        min_confidence: float = 0.40,
        enable_lowercase_fallback: bool = True,
        strict_language_filter: bool = True,
    ) -> None:
        super().__init__(
            model_name=model_name,
            ner_pipeline=ner_pipeline,
            min_confidence=min_confidence,
            enable_lowercase_fallback=enable_lowercase_fallback,
            target_language="en" if strict_language_filter else None,
        )


@register_detector("ner_pl")
class PolishTransformerNERDetector(NERPIIDetector):
    """Dedicated Polish Transformer NER detector (`allegro/herbert-base-cased` / NKJP labels)."""

    def __init__(
        self,
        model_name: str = DEFAULT_POLISH_NER_MODEL,
        ner_pipeline: NERPipelineCallable | None = None,
        min_confidence: float = 0.40,
        enable_lowercase_fallback: bool = True,
        strict_language_filter: bool = True,
    ) -> None:
        super().__init__(
            model_name=model_name,
            ner_pipeline=ner_pipeline,
            min_confidence=min_confidence,
            enable_lowercase_fallback=enable_lowercase_fallback,
            target_language="pl" if strict_language_filter else None,
        )

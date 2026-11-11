"""Pipes & Filters core abstractions, stateless filters, PipelineBuilder, and PipelineProxy."""

from pipeline.builder import PipelineBuilder
from pipeline.context import FilterRecord, PipelineContext
from pipeline.filter import Filter, Pipeline
from pipeline.filters import (
    AnonymizationFilter,
    AuditContextFilter,
    DetectionFilter,
    DocumentExtractorFilter,
    LanguageDetectorFilter,
    ResidencyGate,
)
from pipeline.proxy import PipelineProxy

__all__ = [
    "AnonymizationFilter",
    "AuditContextFilter",
    "DetectionFilter",
    "DocumentExtractorFilter",
    "Filter",
    "FilterRecord",
    "LanguageDetectorFilter",
    "Pipeline",
    "PipelineBuilder",
    "PipelineContext",
    "PipelineProxy",
    "ResidencyGate",
]

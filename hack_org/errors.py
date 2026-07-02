"""Typed operational errors used for retry and alert decisions."""

from __future__ import annotations


class PipelineFatalError(RuntimeError):
    """Base class for fatal errors that should not be retried automatically."""


class CollectionNetworkError(PipelineFatalError):
    """A collection request failed after the proxy/direct policy was applied."""


class ModelConnectionError(PipelineFatalError):
    """The model endpoint could not be reached."""


class ModelAuthError(PipelineFatalError):
    """The configured model API key is missing, invalid, or unauthorized."""


class ModelResponseFormatError(RuntimeError):
    """The model answered but did not satisfy required JSON/schema format."""


class ModelInputRejectedError(RuntimeError):
    """The model provider rejected this specific input and retrying it is wasteful."""


class DatabaseConnectionFatalError(PipelineFatalError):
    """PostgreSQL could not be reached."""


def classify_error(exc: BaseException) -> dict[str, str]:
    """Return a compact classification for logs, model_runs, and reports."""

    if isinstance(exc, ModelAuthError):
        return {"category": "model_auth", "severity": "fatal"}
    if isinstance(exc, ModelConnectionError):
        return {"category": "model_connection", "severity": "fatal"}
    if isinstance(exc, CollectionNetworkError):
        return {"category": "collection_network", "severity": "fatal"}
    if isinstance(exc, DatabaseConnectionFatalError):
        return {"category": "database_connection", "severity": "fatal"}
    if isinstance(exc, ModelResponseFormatError):
        return {"category": "model_format", "severity": "warning"}
    if isinstance(exc, ModelInputRejectedError):
        return {"category": "model_input_rejected", "severity": "warning"}
    name = exc.__class__.__name__.casefold()
    text = str(exc).casefold()
    if "connection" in name or "timeout" in name or "connection" in text:
        return {"category": "network_or_connection", "severity": "fatal"}
    if "auth" in name or "unauthorized" in text or "api key" in text or "401" in text or "403" in text:
        return {"category": "auth", "severity": "fatal"}
    return {"category": "unknown", "severity": "warning"}

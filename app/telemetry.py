"""OpenTelemetry instrumentation setup for jol-auth."""

from fastapi import FastAPI


def setup_telemetry(app: FastAPI) -> None:
    """Initialise OpenTelemetry tracing, metrics, and logging exporters."""
    # TODO: Configure OTEL SDK with OTLP exporter
    pass

"""Compatibility shim. The streaming source is now CT log polling — see ct_log."""
from .ct_log import stream_ct_logs as stream_certificates  # noqa: F401

"""Пакет REST API клиента Nexus."""

from nexus_control.nexus.client import NexusClient, NexusAPIError

__all__ = ["NexusClient", "NexusAPIError"]

"""Threat intelligence feed integration."""

from .threat_feeds import get_threat_feed_client, ThreatFeedClient

__all__ = ["get_threat_feed_client", "ThreatFeedClient"]

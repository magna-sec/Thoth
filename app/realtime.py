"""Realtime fan-out. Publishes events to Redis pub/sub when available; the SSE endpoint
falls back to DB polling when Redis is not configured, so 'live' works either way."""
import json

from flask import current_app

_redis = None
_redis_tried = False


def _client():
    global _redis, _redis_tried
    if _redis_tried:
        return _redis
    _redis_tried = True
    url = current_app.config.get("REDIS_URL")
    if not url:
        return None
    try:
        import redis
        _redis = redis.Redis.from_url(url)
        _redis.ping()
    except Exception:
        _redis = None
    return _redis


def channel(workspace_id):
    return f"ws:{workspace_id}:events"


def publish(workspace_id, event):
    r = _client()
    if r is None:
        return  # SSE will DB-poll instead
    try:
        r.publish(channel(workspace_id), json.dumps(event))
    except Exception:
        pass


def subscribe(workspace_id):
    """Yield event dicts from Redis pub/sub, or None if Redis is unavailable."""
    r = _client()
    if r is None:
        return None
    pubsub = r.pubsub()
    pubsub.subscribe(channel(workspace_id))
    return pubsub

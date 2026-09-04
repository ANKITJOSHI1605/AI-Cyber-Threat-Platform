import json
import math
from pathlib import Path

MODEL_PATH = Path(__file__).parents[2] / "ml" / "url_model.json"


def predict(features: dict) -> dict | None:
    if not MODEL_PATH.exists(): return None
    model = json.loads(MODEL_PATH.read_text())
    source = {"length": features["length"], "subdomains": features["subdomain_count"], "digits": features["digit_count"], "specials": features["special_character_count"], "https": int(features["uses_https"]), "ip_host": int(features["host_is_ip"])}
    normalized = [(source[name] - mean) / scale for name, mean, scale in zip(model["features"], model["means"], model["scales"])]
    value = sum(weight * item for weight, item in zip(model["weights"], normalized)) + model["bias"]
    probability = 1 / (1 + math.exp(-max(-30, min(30, value))))
    return {"probability": round(probability, 4), "model": model["algorithm"], "version": model["version"]}

import csv
import json
import math
from pathlib import Path

ROOT = Path(__file__).parent
FEATURES = ["length", "subdomains", "digits", "specials", "https", "ip_host"]


def sigmoid(value): return 1 / (1 + math.exp(-max(-30, min(30, value))))


def train(rows, iterations=5000, rate=0.08):
    means = [sum(row[i] for row in rows) / len(rows) for i in range(6)]
    scales = [max(1, max(abs(row[i] - means[i]) for row in rows)) for i in range(6)]
    samples = [([(row[i] - means[i]) / scales[i] for i in range(6)], row[6]) for row in rows]
    weights, bias = [0.0] * 6, 0.0
    for _ in range(iterations):
        dw, db = [0.0] * 6, 0.0
        for values, label in samples:
            error = sigmoid(sum(w * x for w, x in zip(weights, values)) + bias) - label
            dw = [current + error * x for current, x in zip(dw, values)]; db += error
        weights = [w - rate * grad / len(samples) for w, grad in zip(weights, dw)]; bias -= rate * db / len(samples)
    predictions = [sigmoid(sum(w * x for w, x in zip(weights, values)) + bias) >= .5 for values, _ in samples]
    accuracy = sum(int(prediction == bool(label)) for prediction, (_, label) in zip(predictions, samples)) / len(samples)
    return {"version": 1, "algorithm": "logistic_regression", "features": FEATURES, "means": means, "scales": scales, "weights": weights, "bias": bias, "training_samples": len(rows), "training_accuracy": accuracy, "dataset_note": "Small curated educational baseline; not a production benchmark."}


if __name__ == "__main__":
    with (ROOT / "url_training_data.csv").open() as handle:
        rows = [[float(row[name]) for name in FEATURES] + [int(row["label"])] for row in csv.DictReader(handle)]
    model = train(rows)
    (ROOT / "url_model.json").write_text(json.dumps(model, indent=2) + "\n")
    print(f"trained {model['training_samples']} samples; training accuracy={model['training_accuracy']:.1%}")

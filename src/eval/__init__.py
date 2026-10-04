"""Evaluation harness: measure detection quality before improving it (v2 phase 1).

``python -m src.eval <command>``:

* ``build``  — assemble a versioned dataset (``eval/datasets/<name>/<version>/``):
  analyst labels, live-verified public phishing feeds and hard negatives
  (official brand logins, homonyms, benign SaaS-hosted pages, Tranco top sites),
  with sanitised URLs, eTLD+1 de-duplication, a temporal train/test split and a
  manifest carrying the samples' SHA-256.
* ``verify`` — check a dataset against its manifest.
* ``run``    — score a split with a predictor (``live``: the deployed multi-API
  detector; ``heuristic``: the same pipeline with every threat-intel provider
  disabled; ``stored``: what the detector said when an analyst labelled the
  site) and write ``report.json`` + ``report.html``.
* ``ops``    — the operational metrics (TTD/TTR/TTT, queues, outcomes) of the
  connected database.
"""

# Import order matters: loading src.detection first resolves the
# src.intelligence <-> src.detection import cycle (src.main, src.api.wsgi and the
# test suite import them in the same order).
import src.detection.analyzer  # noqa: F401

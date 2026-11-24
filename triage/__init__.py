"""Alert explanation and triage on top of the frozen detection method.

This package lives outside ``src/threatdet`` on purpose: the scoring method is frozen for the
LANL days 15-29 holdout (``reports/holdout_freeze.json`` hashes every file under src/, sql/ and
config/). Nothing here can change a detector score; it only reads the fitted models.
"""

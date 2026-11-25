"""Detection-as-code: the host fan-out signal packaged as a scheduled rule with a watch list.

Lives outside src/threatdet/ so the frozen method (reports/holdout_freeze.json) is untouched.
The watch-list design was informed by the days 15-29 diagnosis, so every number it reports is
post-hoc (README "Detection rule").
"""

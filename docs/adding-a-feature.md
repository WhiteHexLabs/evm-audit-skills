# Adding a Feature

Add the feature to `data/features.json` with a description, an explicit
`absence_policy`, and allowed absence evidence kinds. Add its Project Analysis
(`RECON`) mapping to
`data/feature-detectors.json`; structural detector implementations belong in
`scripts/recon.py`, while terms and absence capability stay in the registry.
Presence heuristics must never prove absence. Feature Maps are v5 and carry the
audit source, resolved dependency-source, build-config, and compilation-input
digests.

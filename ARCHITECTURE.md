# Architecture

```
PEM files ─┐
sslyze JSON ├─► adapters ─► list[Finding] ─► classify ─► cyclonedx ─► cbom.json
ssh-audit  ─┤                                  │
vendor CSV ─┘                                  └─► (asset CSV + business inputs X, Y, E, C, D)
                                                        │
                                                        ▼
                                          qesm.score ─► ranked.csv
                                          qesm.sensitivity ─► sensitivity report
```

* Adapters know about one input format each and nothing else.
* `Finding` (src/qraf/model.py) is the only shape that crosses module boundaries.
* `classify` holds every quantum-risk rule in one reviewable place.
* QESM never reads scan output directly: a person supplies X, Y, E, C and D per
  asset, because those are business judgements, not scan results.

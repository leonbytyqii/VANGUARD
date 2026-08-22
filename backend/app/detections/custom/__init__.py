"""
Custom Python / behavioral-correlation detections — for patterns that
don't fit Sigma's single-event model (multi-event correlation over a
time window: brute force, lateral-movement fan-out, impossible travel,
IAM privilege-escalation chains, ...). Each module exposes one class
implementing app.detections.base.DetectionDefinition; app.detections.registry
collects instances of all of them alongside the Sigma-backed rules.
"""

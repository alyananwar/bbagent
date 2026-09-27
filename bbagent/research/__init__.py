"""Research loop: the layer that turns a scanner pipeline into an investigation.

The scanners answer "what matched a template?". This layer answers "what do we
know, what is missing, and which hypothesis does the next request test?" — and
keeps going after the scanners come back empty.
"""

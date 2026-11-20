# lab-mal: adversary placeholder (MVP-07)

This directory is the mount point for the malicious lab that the adversaries
agent provides (image `schild-adversary-malicious-lab:dev`, compose profile
`adversary`). The test-lab agent does not define its behaviour; it only
reserves the slot, the federation network membership and this config mount.
Drop the adversary's `lab.yaml` (and keys) here.

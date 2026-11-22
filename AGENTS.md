# AITactician agent instructions

## Learning loop

- Before non-trivial work, search estate lessons: `python3 ~/Knowledge/scripts/kos.py find "<topic>"` on the Mac, the same `kos.py find "<topic>"` from the knowledge vault's `scripts/` folder on the lab's knowledge server. Research verdicts: TWayneLabs/ai-orchestrator `research/README.md`; decisions: this repository's records, then ai-orchestrator `decisions/operator-decisions.md` (`gh` off the Mac).
- End each handback with `Lesson: none` or one sentence saved first with `kos.py learn` (Mac only). A rule for this repository: `Lesson: rule (<repo>): …`.
- Where `kos.py learn` is not available (the lab's knowledge server, cloud), write `Lesson: unsaved (<repo>): …` in the handback or PR body for this repository's owner to save. Never say it was saved.
- A mistake seen twice becomes a check in this repository (test, lint or pre-commit), not more prose here.

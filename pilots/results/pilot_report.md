# Design partner pilot rehearsal

Scope: fixture rehearsal of the pilot protocol; no design partner, no customer workflow, and no production system was involved. This report does not count toward exit gate B10.

Engineering time: 0.01 s for all three experiments in fixture rehearsal.

| Pilot | Question | Result |
|---|---|---|
| A approval-heavy vs bounded | what does an approval-heavy workflow cost against a bounded autonomous profile on the same tasks? | 12 approval round trips, -0.001 s added wall time |
| B update-caused failures | which update-caused failures (model response, memory, dependency drift) reproduce and get detected? | 4 triggered, 4 reproduced and detected |
| C existing tests vs system faults | which system-level monitor and cleanup faults do the workflow's own checks miss, and what does the system defense contain? | 9 visible without the defense, 9 contained with it |

Willingness to deploy is an operator judgment after a real pilot; this rehearsal records null.

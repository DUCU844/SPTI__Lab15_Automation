Target 10.0.2.15, 1024 ports, 3 runs per row.

| Version | Concurrency | Median time (s) | Min-max (s) | Known open ports found | Missed (worst run) |
|---|---:|---:|---:|---:|---|
| sequential | 1 | 0.081 | 0.071-0.176 | 5/5 | none |
| threads | 50 | 0.634 | 0.368-0.716 | 5/5 | none |
| threads | 200 | 0.481 | 0.390-0.724 | 5/5 | none |
| threads | 500 | 0.427 | 0.423-0.522 | 5/5 | none |
| threads | 2000 | 0.512 | 0.438-0.623 | 5/5 | none |
| asyncio | 50 | 0.259 | 0.217-0.506 | 5/5 | none |
| asyncio | 200 | 0.332 | 0.290-0.516 | 5/5 | none |
| asyncio | 500 | 0.344 | 0.286-0.507 | 5/5 | none |
| asyncio | 2000 | 0.297 | 0.250-0.300 | 5/5 | none |

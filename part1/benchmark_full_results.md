Target 10.0.2.15, 65535 ports, 2 runs per row.

| Version | Concurrency | Median time (s) | Min-max (s) | Known open ports found | Missed (worst run) |
|---|---:|---:|---:|---:|---|
| sequential | 1 | 0.661 | 0.655-0.667 | 5/5 | none |
| threads | 50 | 2.937 | 2.934-2.939 | 5/5 | none |
| threads | 200 | 6.891 | 6.344-7.437 | 5/5 | none |
| threads | 500 | 11.385 | 10.738-12.032 | 5/5 | none |
| threads | 2000 | 10.272 | 10.049-10.495 | 5/5 | none |
| asyncio | 50 | 3.818 | 3.623-4.012 | 5/5 | none |
| asyncio | 200 | 4.819 | 4.755-4.883 | 5/5 | none |
| asyncio | 500 | 5.172 | 5.109-5.235 | 5/5 | none |
| asyncio | 2000 | 1.355 | 1.352-1.358 | 0/5 | 22, 80, 311, 444, 808 |

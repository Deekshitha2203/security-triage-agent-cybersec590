# Demo walkthrough

1. Show the CVE, N02 snapshot, workflow diagram, and R1-R6 policy.
2. Show the baseline's unknown firmware and SSL-VPN settings.
3. Run the baseline and open its assessment, tool trace, and cited evidence. Explain R6 and the missing evidence request.
4. Show the positive scenario's explicit overrides, run it, and explain R1 High / Critical.
5. Show a model-selected tool request and the returned result with the same call ID.
6. Run the tests and show the expected-versus-actual scenario results, including the controlled failure.
7. Explain the remaining uncertainty and recommended actions. Show any completed evidence review.

```bash
python3 -m triage run --scenario baseline --provider duke --evidence-mode auto
python3 -m triage run --scenario positive --provider duke --evidence-mode auto
python3 -m unittest discover -s tests -v
python3 -m triage evaluate
```

Configure credentials before presenting and keep `.env` closed. Each run prints its output directory. Saved demonstrations are linked in [DEMO_RESULTS.md](DEMO_RESULTS.md).

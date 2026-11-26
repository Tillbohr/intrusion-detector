# Team Cache — How we collaborate

Work on the public GitHub repository: https://github.com/Tillbohr/intrusion-detector

1. Pull the latest main: `git checkout main` then `git pull origin main`.
2. Create your own feature branch: `git checkout -b feature/kaleb-rules` (replace name/task).
3. Edit only the files for your component when possible; coordinate changes to shared models.
4. Run `python -m unittest discover -s tests -v` before committing.
5. Commit: `git add .` then `git commit -m "Describe what changed"`.
6. Push: `git push -u origin feature/kaleb-rules`.
7. Open a pull request on GitHub so another teammate can review before merging into main.

Avoid committing `.venv/`, large derived output files, personal paths or credentials. The original project PCAPNG captures are already tracked in the repository. Do not duplicate them in each branch or add other large datasets without agreement.

## Suggested ownership

- Melvin: `cache_ids/packets.py`, `cache_ids/runner.py`, `cache_ids/__main__.py`
- Kaleb: `cache_ids/rules.py` and tests for detection behavior
- Tyler: `evaluate.py`, test measurements, screenshots and demonstration
- Michael: `docs/`, architecture diagram, paper, references, ethics document

Each teammate should record the code version and parameters used for any reported result. Do not claim a test was successful until someone actually ran it against the real capture.

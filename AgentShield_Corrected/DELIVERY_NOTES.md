# AgentShield — Delivery and Verification Notes

**Package:** AgentShield Corrected  
**Verification date:** 31 October 2026  
**Scope:** Preserve the supplied AgentShield project and add real document-content inspection with enforced gateway decisions.

## What changed

- Preserved the original FastAPI/Python backend, React/Vite frontend source, SOC dashboard assets, simulator, agent orchestration, tool gateway, policy modules, audit logging, demo scenarios, and project assets.
- Added `documents/processor.py` for real PDF, DOCX, TXT, and CSV ingestion from uploaded bytes. Upload size, extension, MIME, signature, parser, row/page, and text limits are checked. Malformed, empty, encrypted, unsupported, and invalid files fail closed.
- Added `documents/analyzer.py` for offline content-based threat analysis. It checks direct/indirect prompt injection, system override, credential/secret theft, data exfiltration, unauthorized tools, policy bypass, privilege escalation, suspicious external communications, disclosure attempts, and detectable obfuscation. Findings include redacted excerpts, categories, severity, risk score, and an enforcement result.
- Added scan provenance and server-side records. `ALLOW` content is only passed to the agent as untrusted reference data; `REVIEW` remains quarantined pending an explicit one-time decision; `BLOCK` cannot be accessed by the agent. The agent endpoint accepts scan IDs, not caller-supplied document bodies, and rechecks the stored content hash and private path before use.
- Added upload, scan details, review, and delete APIs, audit events that avoid logging raw extracted contents, secure private extraction storage, local-origin CORS defaults, and deletion of stored extracts when a scan is removed/replaced.
- Integrated upload/review/scan results into the existing Agent Simulator. The React source has a native upload panel; the retained compiled dashboard uses a compatibility bridge so the existing FastAPI-served dashboard also exposes the document workflow without replacing its original visual design.
- Added Windows PowerShell startup/stop scripts, `.env.example`, dependency declarations, and updated README instructions.
- Kept original filename-driven sample scenarios for demonstrations only; they are not used to classify uploaded file contents.

## Verified results

| Check | Result |
|---|---|
| Unified Python unit/integration/regression suite | **162 passed, 2 deselected** (164 collected) |
| Real PDF/DOCX/TXT/CSV extraction and security tests | Included in the passing suite; **19 document-security tests** |
| Python bytecode compilation | Passed |
| Static upload bridge JavaScript syntax | Passed (`node --check`) |
| React frontend source syntax parse | Passed; 20 JS/JSX files parsed |
| Uvicorn backend startup and `/health` | Passed; HTTP 200 |
| Live clean TXT upload → `ALLOW` → agent processing | Passed; agent received scanned content |
| Live malicious upload → `BLOCK` → agent endpoint | Passed; blocked agent call returned HTTP 403 |
| Scan deletion | Passed; extracted file and scan record were removed and subsequent lookup returned 404 |
| CORS smoke test | Local Vite origin allowed; unrelated origin preflight rejected |
| Served dashboard/static bridge | Dashboard HTTP 200; upload bridge asset served successfully |
| ZIP integrity | Verified when package archive is created (see below) |

### Checks not completed in this environment

- **Vite production build:** Not verified. The supplied `node_modules` tree is incomplete for this Linux host (the archived Rollup binary is for another platform). Reinstall/build attempts could not reach `registry.npmjs.org` because DNS/network access was unavailable (`EAI_AGAIN`). The React source was syntax-parsed, and the precompiled original dashboard plus upload compatibility bridge are included. On a connected Windows machine, run `npm ci` and `npm run build` in `frontend/` to generate a fresh bundle.
- **Google GenAI SDK:** The SDK is declared in `requirements.txt` but was not installed in the verification environment because package registry access was unavailable. Exactly two SDK installation/configuration assertions were deselected; the remaining 162 tests passed. The default mock provider runs offline without an API key. Gemini operation needs the SDK, a configured `GEMINI_API_KEY`, and network access.
- **PowerShell execution:** The four `.ps1` scripts are included but could not be executed because PowerShell is not installed in this Linux environment. They need a native Windows smoke test.
- **Browser interaction:** The API and served-dashboard checks passed. A Chromium UI run was blocked by the runtime's browser policy (`ERR_BLOCKED_BY_ADMINISTRATOR`), so a full human-style browser interaction test was not available.
- **OCR:** OCR is not bundled. An image-only PDF, or a PDF with any page that lacks selectable text, returns `OCR_REQUIRED` and is not approved. OCR must be performed externally before re-uploading the document.

## Important security boundaries

- The classifier is a deterministic, local, rule/context-based scanner, not a guaranteed semantic LLM detector. It is designed to work without an API key and errs toward `REVIEW`/`BLOCK` in recognized suspicious cases; it cannot guarantee detection of every novel or deeply obfuscated attack.
- Documents that pass scanning are still untrusted data. The gateway remains responsible for tool authorization; an `ALLOW` decision is not permission to execute instructions contained in the document.
- The review endpoint implements a one-time decision in this local application but does not provide enterprise reviewer identity, SSO, or RBAC. The default CORS setup is local-development oriented. Do not expose this package to a public network without authentication, reviewer identity controls, rate limiting, deployment hardening, and an independent security review.

## Windows quick start

1. Extract the ZIP to a writable folder.
2. Open PowerShell in the project root and run `Set-ExecutionPolicy -Scope Process Bypass` if local script policy requires it.
3. Run `./start_all.ps1`.
4. The script creates `.venv`, installs Python dependencies, validates local configuration, and launches the backend/dashboard. The dashboard is served by the backend; use `./start_frontend.ps1` separately when developing the React/Vite source.
5. Open the URL printed by the startup script. Upload a PDF, DOCX, TXT, or CSV from the Agent Simulator and run its scan.

For manual validation, run `python run_all_tests.py` from the project root. To build the React UI from source, use `cd frontend; npm ci; npm run build` on a machine with registry access.

# veriseal

Software release signing and verification tool for IF4020 Cryptography Assignment 3.

## Local Setup (`uv`)

1. Install `uv` (skip if already installed):
   ```sh
   # macOS / Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Windows (PowerShell)
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

2. Create `.venv` from `uv.lock` (needed for editor autocomplete):
   ```sh
   uv sync
   ```

3. Run the CLI:
   ```sh
   uv run veriseal --help
   ```

4. Add a dependency (updates `pyproject.toml` and `uv.lock` together):
   ```sh
   uv add <package>
   ```

# API Documentation (`veriseal`)

Internal module API documentation for `veriseal` (`cli`, `contracts`, `crypto`, `formats`, `sbom`, `trust`) is generated using [`pdoc`](https://pdoc.dev/) from module docstrings and type annotations in `src/veriseal/`.

- **Hosted URL (GitHub Pages):** https://wiwekaputera.github.io/IF4020-Tugas3-12/
- **Deployment Workflow:** `.github/workflows/deploy-docs.yml`

## Generate Locally

```sh
uvx --with cryptography pdoc --docformat restructuredtext -o docs/_build src/veriseal
```

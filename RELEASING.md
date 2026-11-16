# Releasing to PyPI

`ctfkit` publishes to PyPI automatically when a version tag is pushed, using
**PyPI Trusted Publishing** (OIDC) — no API token is stored in the repo.

## One-time setup

1. Create the project on PyPI (or reserve the name) by doing a first manual
   upload, **or** pre-register a *pending* trusted publisher:
   PyPI → your account → **Publishing** → *Add a pending publisher*:
   - PyPI Project Name: `ctfkit`
   - Owner: `Demian-Chern`
   - Repository name: `rev-pwn`
   - Workflow name: `release.yml`
   - Environment name: `pypi`

2. In the GitHub repo → **Settings → Environments → New environment** named
   `pypi` (matches `environment: pypi` in the workflow). Optionally add required
   reviewers so a human approves each publish.

That's it — no secrets to manage.

## Cut a release

```bash
# 1. bump the version in two places (keep them in sync):
#    - pyproject.toml   -> [project] version
#    - ctfkit/__init__.py -> __version__

# 2. commit, tag, push the tag:
git commit -am "Release vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

Pushing the `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which builds
the sdist + wheel, runs `twine check`, and publishes to PyPI via the trusted
publisher. After it finishes:

```bash
pip install ctfkit
ctfkit --version
```

## Test it first (optional, recommended)

Build and check locally before tagging:

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

To rehearse the upload end to end, point the publisher at **TestPyPI** first
(add a second trusted publisher there and a `testpypi` environment/workflow),
then `pip install -i https://test.pypi.org/simple/ ctfkit`.

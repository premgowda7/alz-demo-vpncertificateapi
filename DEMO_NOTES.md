# ALZ pattern demo — vpn-certificate-api (a device repo)

This is a **demo** on a personal GitHub account. It shows how a *device* repo would
get the same `onboard-to-alz-v3` setup that the *cloud* repos already have.

The original repo (`em-eba-inh-edge-util-vpncertificateapi`) was **not changed**. This is a
separate copy with fresh git history and no secrets.

## What is on this branch

| File | Real or demo | Runs on a personal account? |
|---|---|---|
| `.github/workflows/main.yml` | **Real** ALZ CI caller (copied from the cloud repos, adapted to this repo) | No — calls a company-only workflow |
| `.github/workflows/release.yml` | **Real** ALZ build + deploy caller | No — company-only workflow + self-hosted runners |
| `.github/workflows/iac.yml` | **Real** ALZ IaC caller (exact copy of the cloud file) | No — company-only workflow |
| `.github/workflows/sops-rekey.yml` | **Real** ALZ secret-rekey caller (exact copy of the cloud file) | No — company-only workflow |
| `.github/workflows/ci-cdxgen-bdba.yml` | The repo's existing scan-only CI (left as-is) | No — company-only workflow |
| `.github/workflows/demo-ci.yml` | **Demo only** | **Yes — this is the green run you will see** |
| `.github/demo/requirements_to_sbom.py` | Demo helper used by demo-ci | — |

## Why the real workflows cannot run here

1. They call shared workflows under the **company org**, e.g.
   `EcoStruxure-Building-Activate/em-eba-inh-devops-cicd-templates/...` and
   `EcoStruxure-Building-Activate/DevSecOps-Automation/...`. These do not exist under a
   personal account, so GitHub reports "workflow not found".
2. The build/deploy jobs run on the company's **self-hosted runners**
   (`runs-on: group: eba-vmss-runners`). A personal account does not have them, so jobs
   would wait forever.
3. They need Azure, the JFrog registry and an AKS cluster, none of which exist here.

So on this account: **do not click "Run workflow"** on main/release/iac/sops-rekey —
they will error. Only `demo-ci` runs, and it goes green.

## What the real task still needs (for Monday, in the company org)

- A Helm chart at `./helm` (this repo has none yet). `release.yml` deploys that chart.
- An `iac/` folder with a `.sops.yaml` and the per-environment encrypted values, like the
  cloud repos have, for `iac.yml` to plan/apply.
- Confirm three names with the platform team: `image_repo`, `release_name`, `namespace`
  in `release.yml` (they are best guesses here).
- Decide whether `main.yml` replaces the existing `ci-cdxgen-bdba.yml` or runs beside it.
- Confirm which repos count as "device repos" for this rollout.

## How the demo CI proves itself (no fake passes)

`demo-ci.yml` runs three real steps: compile every Python file, build a real CycloneDX
SBOM from `requirements.txt`, and upload it as an artifact. Tested locally on Python 3.12
before pushing: `compileall` exits 0 and the SBOM script writes a valid file.

## Security finding (pre-existing in the original repo)

While preparing this demo I found a **hardcoded authorization token** in `constant.py`
(`AUTHORISATION_TOKEN = "..."`) in the original repo. It is used by `app.py` to check the
`Authorization` header. For this demo it was changed to read from an environment variable
(`os.environ.get("AUTHORISATION_TOKEN", "")`) so no secret is published, and the git
history here was rebuilt so the token is in no commit.

This issue still exists in the real repo `em-eba-inh-edge-util-vpncertificateapi` on `main`.
Recommended real fix: move the token to the secret store / an env var and rotate it.

The full picture of the cloud pattern, and the per-repo analysis, is in the
`REPOS-analysis` folder next to the workspace.

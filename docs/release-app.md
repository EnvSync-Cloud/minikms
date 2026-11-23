# Release app

The release bump workflow (`.github/workflows/release-bump.yml`) pushes the rc bump commit and the annotated rc tag with a GitHub App token. The workflow `GITHUB_TOKEN` stays read-only. A tag push from this app is what starts [`.github/workflows/release.yaml`](../.github/workflows/release.yaml). A push made with `GITHUB_TOKEN` does not start that workflow.

Install the app on `EnvSync-Cloud/minikms` only.

Repository permissions:

| Permission | Access |
| --- | --- |
| Contents | Read and write |
| Metadata | Read-only |

Grant nothing else.

Repository variables:

| Name | Value |
| --- | --- |
| `RELEASE_APP_ID` | GitHub App id |
| `RELEASE_APP_SLUG` | GitHub App slug. The commit author is `<slug>[bot]`. |

Repository secret:

| Name | Value |
| --- | --- |
| `RELEASE_APP_PRIVATE_KEY` | GitHub App private key (PEM) |

A merged pull request into `dev` runs the bump workflow. It writes the next `X.Y.Z-rc.N` into `VERSION`, commits that file, and pushes the annotated tag `vX.Y.Z-rc.N`. `workflow_dispatch` is the owner-run path for an rc of the current `dev` tip. The manual rc fallback is owner-only: set `VERSION` to the rc version with `make bump SPEC=X.Y.Z-rc.N`, commit and push that change to `dev` through the normal path, then create the matching annotated tag on that commit and push the tag. The release workflow checks that `VERSION` matches the tag.

When `RELEASE_APP_ID` is unset, the workflow warns `release app not configured; no rc created` and exits successfully.

Phase B adds a ruleset on `dev`. That ruleset needs this app as a bypass actor so the bump push can update `dev`.

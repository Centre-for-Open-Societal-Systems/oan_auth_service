# Git Workflow and Merge Hygiene

Branching, commits and conflict-free files for every OAN Frappe app. Most merge conflicts
have the same shape: two branches append to the end of one file, or one branch reformats a
file another is editing. The rules below remove both.

## 1. Branches and Commits

- Branch from the latest `develop`. Never commit directly to `develop` or `main`.
- Branch names: `feat/…`, `fix/…`, `test/…`, `docs/…`, `refactor/…`, `chore/…`.
- Commit messages follow Conventional Commits, checked by `commitlint.config.mjs`.
  Allowed types: `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`,
  `revert`, `style`, `test`. Type is lower case; subject is not empty. Use a scope when it
  helps: `feat(auth): …`.
- Merge `develop` into the feature branch early and often.

## 2. Files That Conflict

`.gitattributes` in every app sets:

```gitattributes
* text=auto eol=lf
<app_name>/patches.txt merge=union
<app_name>/modules.txt merge=union
*.md diff=markdown
*.py diff=python
uv.lock linguist-generated=true
```

- `patches.txt` and `modules.txt` are append-only registries. `merge=union` keeps both
  sides when two branches append; if
  you ever rename or drop an entry, union keeps the stale line too, so read the merged
  file before you commit.
- `end-of-file-fixer` keeps a final newline on every file, so an append does not rewrite
  the previous last line.
- Do not reformat code or docs you are not changing. Let the formatters do it.
- In docs, append new endpoint sections at the end of their chapter with the next number.
  On a numbering clash, keep both and renumber; never delete a section to resolve it.
- Regenerate generated files (specs, gateway config, lock files) after a merge; never
  hand-merge them.

Recommended once per machine:

```bash
# Show the common ancestor in a conflict, not only the two sides.
git config --global merge.conflictStyle zdiff3
# Record conflict resolutions and replay them on the next re-merge.
git config --global rerere.enabled true
```

## 3. Pull Requests

Before opening a PR, run `git status` to confirm DocType JSON, patches and generated files are staged and no debug
files are. The PR description lists the summary, key changes, related issue, and the
verification checklist.

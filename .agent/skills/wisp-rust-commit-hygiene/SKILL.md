---
name: wisp-rust-commit-hygiene
description: Inspect and protect Git boundaries before branch, staging, commit, merge, history rewrite, push, or PR work in wisp-rust, the Wisp proxy server workspace. Use for reviewing dirty trees, separating other sessions' changes, keeping benchmark output and private provider code out of public history, or preparing any Git mutation. Commit completed changes frequently under standing authorization. Pushing, rewriting history and changing branches need separate authorization.
---

# Keep wisp-rust history clean

Load this skill before any Git mutation beyond read-only inspection.

## Inspect first

Run in the wisp-rust Git root (`wisp-rust/`, not `../wisp-rust-proxy-providers`):

```sh
git status --short --branch
git remote -v
git diff --stat
git diff --cached --stat
git diff --cached
```

Classify pre-existing work and current-task changes. Other sessions often leave server and bench files modified here; never stage, discard or reset them. Do not bypass hooks.

Split mixed dirty trees. One commit is one product change: one crate's behavior, a bench, CI or a dependency update each go alone.

## Commit authorization and cadence

Commit your own completed feature or fix slices frequently after their relevant checks pass (`cargo check --tests -p <touched-crate>`, `cargo fmt --check`, and `cargo deny check` for a dependency change). This is standing authorization from the owner: do not ask before routine commits and do not defer all commits to the end of a long task.

Commit only your own changes. Authorization to commit never authorizes pushing, creating, switching or merging branches, publishing, amending, or rewriting history. Each needs separate authorization unless the session already provides it.

## Remotes and branches

| Remote | Address | Use |
| --- | --- | --- |
| `origin` | `https://browserports.dev/BrowserPorts/wisp-rust.git` | Forgejo. The only push target. |

- `main` carries the server. Topic branches (`feat/`, `fix/`, `perf/`, `bench/`, `ci/`) are merged into `main` with `git merge --no-ff`, which keeps the `Merge branch '<topic>'` commits the history already uses. Create, merge or push a topic branch only when asked.
- `feat/ip-tunnel`, `feat/ip-tunnel-client` and `stellite-front-retry` live on Forgejo. Do not push or delete them unless asked.
- This repository is public. Forgejo pushes it to the read-only mirror at `github.com/BrowserPorts/wisp-rust`. Reach GitHub only through that mirror: never push to GitHub directly and never add a GitHub push remote.

## Repository isolation

The proxy provider crates are a private repository at `../wisp-rust-proxy-providers`. `Cargo.toml` already patches them to that checkout; add no other `path` dependency that leaves this workspace, and never stage that repository's files or copy its sources here.

## Staging

Inspect every untracked path. Never stage:

- `target/`, `dist/`, `node_modules/`, `vendor/`, `.local/`, `.cargo/`, `*.tsbuildinfo`
- built native output: `*.node`, `*.dylib`, `*.pdb`, msquic libraries and their notices
- `scripts/`, which is local to each clone
- `.env`, `.env.*`, certificates, keys, upstream proxy credentials
- benchmark runs, captures and logs that are not the committed results a bench change records

`.agent/`, `.agents/`, `.claude/`, `AGENTS.md` and `CLAUDE.md` are ignored in the tracked `.gitignore`. Only this skill and its two discovery links are tracked there; stage a new file under them with `git add -f -- <exact path>` only when it is a skill meant for every clone.

`Cargo.lock` changes only with a dependency change, written by Cargo. Stage exact paths, then rerun status and inspect the complete staged diff. Unstage a prohibited path with `git restore --staged -- <path>`; do not discard its working copy.

## Commit messages

Use Conventional Commits:

```text
<type>(<scope>): <imperative technical summary>
```

- Keep the subject at or below 72 characters.
- Describe product behavior and technical rationale only.
- Use the configured human author and committer.
- No AI or model attribution of any kind: no `Co-Authored-By` naming Claude or Anthropic, no `noreply@anthropic.com`, no `Claude-Session` line, no generated-by line. Forgejo's pre-receive hook refuses a push that brings in such a commit.
- No sessions, prompts, task or rule numbers, agents, waves, worktrees, workflows, checkpoints, plans, transcripts, or process narration.

Scan the exact proposed message before committing:

```sh
rg -ni 'co-authored-by:.*(claude|anthropic|ai)|claude-session|assisted-by|generated(-by| with)|task ?#|rule ?#|#[0-9]|iter-|wave|refuter|worktree|workflow|goal-mode|checkpoint|transcript'
```

No matches are permitted.

## Pushing

- Push only to `origin` on Forgejo, and only when authorized. `git remote get-url --push origin` must print the Forgejo URL. Never push to Cursor's origin (`origin.cursor.com`) or to GitHub.
- Push one branch with an explicit refspec: `git push origin main:main`. Never `--force`, `--all`, `--mirror`, or a bare `git push`.
- Scan the whole outgoing range first, including commits already ahead of the remote and those a merged topic branch brings:

```sh
git log --format='%H%n%B' origin/main..HEAD | rg -ni 'co-authored-by:.*(claude|anthropic)|noreply@anthropic\.com|claude-session|generated(-by| with)'
```

- If Forgejo refuses a push, report why. Do not rewrite history or work around the hook.

## Safeguards

- Never use `--no-verify`.
- Never amend a pushed commit, force-push, or rewrite shared history without explicit approval.
- Reinspect `git show --stat --oneline --decorate HEAD` and status after every commit.

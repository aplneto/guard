# Agent Guard — Initial Specification

Oct 9, 2026 · @apneto

## Overview

Agent Guard (`guard`) is a Rust launcher that starts an AI coding agent inside a kernel-enforced sandbox, so file, process and network rules hold no matter which program the agent uses to break them.

**Problem.** Today's agent guardrails mostly match command text. An agent told not to read `.env` via `cat` simply ran `python -c "open('.env').read()"`, and the rule never fired. Any rule enforced on command strings can be routed around by another interpreter, a script file, `eval`, or the agent's own built-in file tools, which never touch bash.

**Approach.** Enforce at the kernel boundary instead. `guard run -- claude` builds a sandbox (Linux namespaces + Landlock, later seccomp and cgroups), then execs the agent inside it. Every tool call, shell, script and grandchild process inherits the restrictions and cannot drop them.

**Goals**

- Secret files (e.g. `.env`, `~/.ssh`, cloud credentials) are unreadable by the agent and every descendant, through any language or tool.
- Writes are confined to the project directory and explicitly allowed paths.
- Network access can be switched off per policy.
- One TOML policy works for Claude Code, Antigravity and any other CLI agent.
- Runs unprivileged (no root, no setuid) on a stock modern Linux kernel.
- Clear, actionable errors when the agent hits a rule.

**Non-goals (for now)**

- macOS or Windows support.
- Parsing or rewriting bash commands.
- Defending against kernel exploits or a hostile local user.
- Replacing containers or VMs for fully untrusted workloads.

## Threat model

The adversary is the agent process tree itself: a well-meaning model making mistakes, or a model steered by prompt injection from a file, web page or tool output. Both are treated the same way, as untrusted code running with the developer's user ID.

**In scope**

- Reading protected files by any route: shell tools, interpreters (Python, Node, Ruby), compiled binaries, symlinks, hard links, `/proc/self/root`, the agent's built-in read tool.
- Writing or deleting outside allowed paths.
- Exfiltrating data over the network when network is disabled.
- Escaping the sandbox by spawning detached processes, `setsid`, double-forking or `nohup`.
- Runaway process trees (fork bombs, leaked dev servers) once cgroups land.

**Assumptions**

- The kernel is trusted and recent enough (see Enforcement details).
- `guard` itself and the policy file are not writable from inside the sandbox.
- The developer launches the agent through `guard`, not directly.

**Out of scope**

- Kernel or hardware vulnerabilities.
- Side channels and timing attacks.
- Data the developer pastes into the agent's prompt by hand.
- What the agent's remote API provider sees: anything the agent legitimately reads is sent to the model.

## Architecture

`guard` wraps the whole agent, not just its shell: the agent and everything it spawns run inside one sandbox the kernel enforces, so no route to a file bypasses the rules.

&#91;embedded content: architecture · supervisor, sandbox, kernel enforcement\]

The supervisor stays on the host and never runs agent code. Inside, a tiny init is PID 1 so the agent gets normal signal handling and orphaned processes are reaped; when the agent exits, init exits and the kernel kills anything left in the namespace.

## CLI interface

The MVP ships three subcommands; everything else comes later.

| Command | Purpose |
| --- | --- |
| `guard run [OPTIONS] -- <cmd> [args...]` | Build the sandbox from the resolved policy and exec `<cmd>` inside it. |
| `guard check [--policy PATH]` | Validate the policy, print the resolved rules, and report kernel support (Landlock ABI, user namespaces). |
| `guard explain <path>` | Print whether a path is readable, writable or masked under the current policy, and which rule decided. |

**Options for `guard run`**

- `--policy <PATH>`: use this file instead of the default lookup.
- `--project <DIR>`: project root (default: current directory).
- `--no-network`: force network off regardless of policy.
- `--dry-run`: print the sandbox plan and exit without launching.
- `-v` / `-vv`: log sandbox setup steps to stderr.

**Exit codes**

| Code | Meaning |
| --- | --- |
| 0–124 | Passed through from the wrapped command. |
| 125 | `guard` failed before launch (bad policy, setup error). |
| 126 | Kernel lacks a required feature and `fail_open = false`. |
| 127 | Wrapped command not found. |

Codes 125–127 follow the convention used by `env` and `timeout`, so scripts can tell guard errors from agent errors.

## Policy file format

Policies are TOML, deny-by-default for writes and masked paths, and resolved from three layers so a team can share a baseline while each repo tightens it.

**Resolution order** (later layers add rules; a `mask` can never be removed by a later layer)

1. Built-in defaults compiled into `guard`.
2. User file: `~/.config/agent-guard/policy.toml`.
3. Project file: `<project>/.agent-guard.toml`, read-only inside the sandbox.

**Example**

```toml
version = 1
fail_open = false            # refuse to launch if Landlock is unavailable

[filesystem]
# Paths support ~, $PROJECT and glob patterns.
read_only  = ["/usr", "/lib", "/lib64", "/bin", "/etc", "~/.cargo", "~/.rustup"]
read_write = ["$PROJECT", "/tmp", "~/.cache"]

# Masked paths look empty inside the sandbox, whatever reads them.
mask = [
  "$PROJECT/**/.env",
  "$PROJECT/**/.env.*",
  "~/.ssh",
  "~/.aws",
  "~/.config/gcloud",
  "~/.kube",
]

[network]
mode = "allow"               # "allow" | "deny"; "allowlist" planned for later

[process]
max_pids = 512               # enforced once cgroups land

[agent]
# Extra paths the agent itself needs (config, session state).
read_write = ["~/.claude", "~/.claude.json"]
```

**Semantics**

- Anything not listed under `read_only` or `read_write` is inaccessible.
- `mask` beats `read_only` and `read_write` for the same path.
- Glob masks are expanded at launch; files created later that match a mask are not hidden in the MVP (see Open questions).
- Unknown keys are an error, so typos never silently weaken a policy.

## Enforcement details

The sandbox is built in a fixed order, each step narrowing what the next can do, and everything is applied before the agent's first instruction runs.

**Setup sequence for `guard run`**

1. Load and validate the policy; resolve globs and `~` to absolute paths.
2. Probe the kernel: Landlock ABI version, unprivileged user namespace support. Abort (exit 126) if a required feature is missing and `fail_open = false`.
3. `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)`, plus `CLONE_NEWNET` when network is denied. Map the caller's UID/GID to itself so file ownership looks normal.
4. Make all mounts private (`MS_REC | MS_PRIVATE`) so nothing leaks back to the host.
5. Mask secrets: bind-mount an empty read-only file over each masked file, and an empty read-only tmpfs over each masked directory.
6. Bind the project policy file read-only over itself.
7. Fork. The child becomes PID 1 of the new PID namespace (a minimal init) and mounts a fresh `/proc`, hiding host processes, then forks the agent process, which runs steps 8 and 9.
8. Set `PR_SET_NO_NEW_PRIVS`, then apply the Landlock ruleset built from `read_only` and `read_write`.
9. Exec the agent. Capabilities gained from the user namespace are dropped on exec, because the agent runs as a non-root UID.

**Why the masks can't be undone.** Removing a bind mount needs `CAP_SYS_ADMIN` in the namespace, which the agent loses at exec (step 9). Landlock also forbids sandboxed processes from changing mount topology. In v0.2 a seccomp filter adds a third layer by denying `mount`, `umount2`, `unshare`, `setns`, `pivot_root` and `ptrace` outright.

**Why both Landlock and mount masking.** Landlock only grants access to path hierarchies; it cannot say "all of `$PROJECT` except `.env`". Masking covers the exceptions, Landlock covers everything outside the allowlist.

**Network.** `deny` means an empty network namespace with only loopback up. A namespace is used rather than Landlock's network rules because those cover TCP only, not UDP or raw sockets.

**Process lifetime.** The `guard` supervisor stays outside as the parent, forwards signals, and passes the agent's exit code through. Init exits as soon as the agent does, and when PID 1 of the namespace exits, the kernel kills every remaining process in it, so `nohup`, `setsid` and double-forked daemons cannot outlive the session.

**Kernel requirements**

| Feature | Minimum kernel | Used for |
| --- | --- | --- |
| Landlock ABI 1 | 5.13 | Filesystem allowlist (hard requirement) |
| Landlock ABI 3 | 6.2 | Controlling file truncation |
| Unprivileged user namespaces | Distro-dependent | Mount masking, PID and network isolation |
| seccomp user notification | 5.0 | v0.2 audit supervisor |
| cgroup v2 + systemd user delegation | Distro-dependent | v0.3 resource limits |

**Ubuntu caveat.** Ubuntu 23.10 and later restrict unprivileged user namespaces through AppArmor (`kernel.apparmor_restrict_unprivileged_userns`). `guard` will need an AppArmor profile, installed once with root, that permits it to create user namespaces; `guard check` must detect and explain this.

## Repository layout and crate choices

A Cargo workspace with a thin binary over a policy crate and a sandbox crate, so the policy logic is unit-testable without touching the kernel.

```
agent-guard/
├── Cargo.toml                 # workspace
├── crates/
│   ├── guard-cli/             # binary: argument parsing, wiring, exit codes
│   │   └── src/main.rs
│   ├── guard-policy/          # TOML schema, layering, glob resolution, `explain`
│   │   └── src/{lib.rs, schema.rs, resolve.rs}
│   └── guard-sandbox/         # namespaces, mounts, Landlock, launcher (Linux only)
│       └── src/{lib.rs, probe.rs, ns.rs, mask.rs, landlock.rs, launch.rs}
├── policies/
│   └── default.toml           # built-in defaults, embedded with include_str!
├── packaging/
│   └── apparmor/agent-guard   # profile for Ubuntu 23.10+
├── tests/
│   ├── escape/                # bypass-attempt scripts (see Testing strategy)
│   └── integration.rs
└── docs/
    └── SPEC.md                # this document
```

| Crate | Use |
| --- | --- |
| `clap` (derive) | CLI parsing |
| `serde` + `toml` | Policy parsing with `deny_unknown_fields` |
| `globset` + `walkdir` | Expanding mask globs |
| `landlock` | Official Rust bindings, with best-effort ABI compatibility |
| `nix` or `rustix` | `unshare`, `mount`, `fork`, `prctl`, UID/GID maps |
| `thiserror` / `anyhow` | Library errors / binary errors |
| `tracing` + `tracing-subscriber` | `-v` logging |
| `assert_cmd` + `tempfile` | Integration tests |
| `seccompiler` or `libseccomp` | v0.2 syscall filter and audit |

Keep every `unsafe` block in `guard-sandbox`, each with a comment stating the invariant it relies on; `guard-policy` and `guard-cli` use `#![forbid(unsafe_code)]`. Note the classic trap: after `fork` in a multithreaded process only async-signal-safe calls are allowed, so do all allocation and path resolution before forking and keep the process single-threaded until exec.

## Testing strategy

The acceptance bar is an escape suite: every known bypass route runs inside `guard run` against a fixture project and must fail, in CI, on every commit.

**Escape suite (MVP)** — each case tries to read a planted `.env` containing a canary string; the test passes only if the canary never appears on stdout or in a file outside the sandbox.

| Route | Example attempt |
| --- | --- |
| Shell tools | `cat .env`, `head`, `grep -r CANARY .` |
| Interpreters | `python3 -c "print(open('.env').read())"`, `node -e`, `perl -ne` |
| Compiled binary | A small static C or Rust binary calling `open(2)` directly |
| Symlink | `ln -s .env x && cat x` |
| Hard link | `ln .env x && cat x` |
| procfs | `cat /proc/self/root$PWD/.env`, `/proc/1/cwd/.env` |
| Unmount | `umount .env`, `unshare -m` then `umount` |
| Copy tools | `cp .env /tmp/x`, `tar c .env`, `git add .env && git show` |
| Masked dir | `ls ~/.ssh`, `cat ~/.ssh/id_ed25519` |
| Write escape | `touch ~/outside`, `echo x > /etc/foo` |
| Detached process | `setsid sleep 999 &` must be gone after `guard` exits |
| Network (deny) | `curl https://example.com`, a raw UDP DNS query |

**Other layers**

- Unit tests in `guard-policy`: layering, mask precedence, glob expansion, `explain` output, rejection of unknown keys.
- Integration tests: `guard check` on kernels with and without Landlock (CI matrix with at least one older and one current kernel image).
- Smoke test with a real agent: launch Claude Code under `guard`, ask it to read `.env` via its built-in tool and via Python, and confirm both fail with a readable error.
- Every bug report that turns out to be a bypass becomes a new escape case before it is fixed.

## Milestones

v0.1 is done when the escape suite passes in CI and Claude Code can't read `.env` by any route; each later release adds one layer and moves on only when its gate is met.

&#91;embedded content: roadmap · 3 releases, 3 gates\]

Scope inside a release can shift, but nothing from v0.2 onward starts until the v0.1 gate is green: a sandbox that leaks makes audit logs and limits pointless.

## Open questions

- [ ] Name: is `agent-guard` / `guard` free of clashes with tools the team already uses?
- [ ] New secret files: a `.env` created after launch is not masked. Accept for MVP, re-scan on a timer, or deny file creation matching mask globs via the v0.2 supervisor?
- [ ] Agent state: each agent keeps config and sessions in different places (`~/.claude`, Antigravity's equivalent). Ship per-agent presets, or make users list them?
- [ ] Git credentials: pushing needs `~/.ssh` or a credential helper. Mask by default and let the human push, or allow an SSH agent socket through?
- [ ] Network allowlist: is per-domain filtering (e.g. allow only the model API and package registries) needed in the first year? It requires a proxy, not just a namespace.
- [ ] Distribution: static musl binary on GitHub Releases, a `.deb`, or `cargo install` only? The AppArmor profile pushes towards a package.

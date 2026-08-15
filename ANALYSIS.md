# galera-status — Code Analysis: Suggested Fixes & Optimizations

Analysis of `galera-status` (v1.1, bash, ~520 lines) as of commit `15b90e7`.
Findings are ordered by severity. Line numbers refer to the script *as analyzed*
(commit `15b90e7`), not the fixed version.

> **Status update:** all findings except 3.6 (dynamic command-row placement) and
> 4.3 (parallel node polling) have been applied on this branch in the commit
> following this document. The password handling from 3.1 was implemented via
> `MYSQL_PWD` rather than a `--defaults-extra-file`, and a `--interval=<seconds>`
> option was added along with the follow-mode pacing fix (4.2).

---

## 1. Critical bugs

### 1.1 `--hosts` mode is completely broken by empty quoted arguments (regression)

**Where:** `galera-status:194`, `327`, `374`, `410`

```bash
mysql "$@" -h "$host" "$username" "$password" $connect_timeout ...
```

When `--hosts` is used, `$username` and `$password` are unset (or set to `""` when the
user passes `-u`/`-p`). Because they are **quoted**, bash passes two *empty positional
arguments* to `mysql`. Verified with MariaDB client 10.11: the client treats them as
positional arguments (database name + extra) and aborts with a usage error **before
attempting any connection**. Since stderr is discarded (`2> /dev/null`), every node
silently shows `OFFLINE`, and `check_privileges` also fails so the weight command is
disabled.

This is a regression introduced in commit `8f48cb8` ("Fix all shell script errors and
warnings"): the original unquoted `$username $password` collapsed to nothing when empty.
The shellcheck-appeasing quoting changed the behavior.

**Fix:** use an array so empty credentials contribute zero arguments:

```bash
mysql_auth=()
# where credentials are resolved from sst-auth:
mysql_auth=(-u"$sst_user" -p"$sst_pass")

# at every call site:
mysql "$@" -h "$host" "${mysql_auth[@]}" $connect_timeout -N -B -e "..."
```

The same array technique should be applied to `$connect_timeout`
(`timeout_opt=(--connect-timeout=2)`), which currently only works because it is
deliberately left unquoted.

### 1.2 `eval` on server-supplied values — code-injection risk

**Where:** `galera-status:189-194`

```bash
while read -r varname value; do
  varname=${varname/wsrep_}
  eval "$varname='$value'"
done < <(mysql ... -e "SHOW STATUS LIKE 'wsrep_%'; ...")
```

Every value returned by the server is passed through `eval`. A value containing a single
quote breaks out of the quoting and executes arbitrary shell code with the privileges of
the monitoring user. `wsrep_provider_options` is a free-form string (settable via
`SET GLOBAL` by any privileged DB user, and fully controlled by a compromised/malicious
server), so this is a realistic attack path for a *monitoring* tool that is often run as
root on DB nodes. Even without malice, any status value containing `'` crashes the parse.

**Fix:** never `eval` external data; use `printf -v` and whitelist the variable name:

```bash
while IFS=$'\t' read -r varname value; do
  varname=${varname#wsrep_}                                # strip prefix only (see 3.2)
  [[ $varname =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue   # reject weird names
  printf -v "$varname" '%s' "$value"
done < <(mysql ...)
```

### 1.3 `unsci` corrupts values ending in "00"

**Where:** `galera-status:153-159`

```bash
echo "${unscivalue%%+(00)}"
```

The extglob `+(00)` strips trailing zero *pairs* regardless of a decimal point.
Verified behavior:

| input  | output | correct? |
|--------|--------|----------|
| `100`  | `1`    | ❌ 100× too small |
| `1200` | `12`   | ❌ 100× too small |
| `0.500000` | `.50` | ✓ (cosmetic) |

`wsrep_local_send_queue_avg` / `recv_queue_avg` can legitimately be ≥ 100 on a struggling
cluster — precisely the situation where the operator relies on this display. The red
highlighting still triggers, but the number shown is wrong by a factor of 100.

**Fix:** only trim zeros after a decimal point — or better, drop `unsci` entirely
(see optimization 4.1):

```bash
[[ $unscivalue == *.* ]] && unscivalue=${unscivalue%%+(0)} && unscivalue=${unscivalue%.}
```

---

## 2. Functional bugs

### 2.1 Capital `Q` does not quit in follow mode

**Where:** `galera-status:488` vs `497`

The inner loop breaks on `q` **or** `Q`, but the outer `while [ "x$keypress" != "xq" ]`
only tests lowercase `q`. Pressing `Q` in follow mode breaks the host loop, the outer
loop re-iterates, `keypress` is overwritten by the next `cat -v` — and the script keeps
running. Fix:

```bash
while [[ $keypress != [qQ] ]]; do
```

### 2.2 `-u`/`-p` override happens *after* `check_privileges`

**Where:** `galera-status:458-461` (privilege check) vs `468-478` (override loop)

When running on a cluster node with sst-auth auto-detection *and* explicit `-u`/`-p`
options, `check_privileges` (and only it) is executed while `$username`/`$password` are
still populated from sst-auth. Since those come **after** `"$@"` on the mysql command
line, they override the user's explicit credentials for the privilege check. Move the
override loop above the `check_privileges` call.

### 2.3 `r` (reset replication health) only flushes one node

**Where:** `galera-status:326-334`, `500`

`FLUSH STATUS` is executed against whichever `$host` happens to be current in the poll
loop when the key is read — effectively a random node — while the UI says
"Reset replication health status" (implying the cluster). Loop over all hosts:

```bash
for h in "${hosts[@]}"; do
  mysql "$@" -h "$h" "${mysql_auth[@]}" "${timeout_opt[@]}" -N -B -e "FLUSH STATUS;"
done
```

### 2.4 sst-auth password containing `:` is truncated

**Where:** `galera-status:453`

```bash
cut -d':' -f2
```

`wsrep_sst_auth` is `user:password`; a password containing `:` is cut off. Use `-f2-`.

### 2.5 No handling of zero resolved hosts

**Where:** `galera-status:444-456`

If auto-detection fails (no `mysqld` in `PATH` — it typically lives in `/usr/sbin` — or
not a Galera node) and `--hosts` was not given, `hosts` is empty and the script clears
the screen, prints nothing, and exits 0. Print an actionable error and `exit 1` when
`host_count -eq 0`. Also consider probing `/usr/sbin/mysqld` as a fallback.

### 2.6 Literal `divider_size` passed to `hr`

**Where:** `galera-status:329`, `331`, `339`, `356`, `373`, `375`, `515`

```bash
$(hr divider_size ' ')
```

This only works because `(( i < $1 ))` re-evaluates the string `divider_size` as a
variable name inside the arithmetic context — an accident, not a feature (and it breaks
if `hr` is ever rewritten with `[ ]` or `printf '%*s'`). Pass `"$divider_size"`.

---

## 3. Security & robustness

### 3.1 Password on the command line

`-p$password` is visible in `ps`/`/proc/*/cmdline` on the monitoring machine for every
poll (once per node per refresh cycle). Prefer `MYSQL_PWD` (still env-visible but not in
`ps`) or, best, a generated `--defaults-extra-file`:

```bash
tmpcnf=$(mktemp); chmod 600 "$tmpcnf"
printf '[client]\nuser=%s\npassword=%s\n' "$sst_user" "$sst_pass" > "$tmpcnf"
mysql --defaults-extra-file="$tmpcnf" ...
```

### 3.2 `${varname/wsrep_}` strips the first occurrence anywhere, not the prefix

**Where:** `galera-status:191` — use `${varname#wsrep_}` (prefix removal). Currently a
hypothetical `wsrep_foo_wsrep_bar` mangles unexpectedly; prefix form documents intent.

### 3.3 `get_value_from_provider_options` uses an unanchored regex

**Where:** `galera-status:162` — `grep "$1"` with `pc.weight`: `.` matches any char and
substring matches are possible. Use `grep -E "^\s*${1//./\\.}\s*="` or match with `awk -F=`.
Also trim whitespace from the extracted value (`pc.weight = 1` → `" 1"` today, which
makes the displayed `node/cluster weight` misaligned).

### 3.4 Missing dependency checks

`bc` is required (three call sites) but never checked; on a minimal container the health
columns silently misbehave. Either check at startup (`command -v bc || die`) or remove
the dependency entirely (see 4.1).

### 3.5 `stty size` with no tty

**Where:** `galera-status:395` — when stdin is not a terminal (cron, CI, piped),
`stty size` fails and `terminal_width` is empty, producing arithmetic errors. Fall back:
`terminal_width=$(stty size 2>/dev/null | cut -d' ' -f2); : "${terminal_width:=${COLUMNS:-120}}"`.

### 3.6 Fixed 31-row layout

`CMD_ROW=31` places the command bar off-screen on terminals shorter than 31 rows, and
resize handling (`update_terminal_width`) only reacts to width. Derive from
`$(stty size | cut -d' ' -f1)` with 31 as a minimum, or at least document the
requirement.

---

## 4. Optimizations

### 4.1 Replace `unsci` (sed + bc + extglob) with builtin `printf`

Bash's builtin `printf` parses scientific notation natively:

```bash
printf '%.6f' "5.9e-05"   # → 0.000059
```

This removes the `sed` regex, the `bc` dependency and the trailing-zero bug (1.3) in one
move — 3 forked processes per value per node per refresh cycle become 0. The `> 0.1`
threshold comparisons can then use one `awk` (or stay on `bc` if kept):

```bash
float_gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>b)}'; }
```

### 4.2 Follow mode is a busy loop — add a refresh interval

**Where:** `galera-status:488-510`

The tty is set to `time 0 min 0` and `cat -v` returns immediately, so the loop re-polls
every node as fast as mysql round-trips allow: constant CPU on the monitoring host and a
steady query load (2 result sets + privileges worth of traffic × N nodes, continuously)
on the cluster. Add a pacing read between cycles, which doubles as the key poll:

```bash
IFS= read -rsn1 -t "${REFRESH_INTERVAL:-1}" keypress   # 1 s pause, wakes early on keypress
```

(and drop `cat -v`). Consider a `--interval=N` option.

### 4.3 Poll nodes in parallel

Each refresh polls nodes sequentially; with the 2 s connect timeout, a single dead node
freezes the whole display for 2 s per cycle. Fan the `mysql` calls out to temp files
(`for h in ...; do query "$h" > "$tmp/$h" & done; wait`) and render afterwards — makes
refresh latency O(slowest node) instead of O(sum of nodes).

### 4.4 Batch the two credential greps

**Where:** `galera-status:447-454` — `mysqld --verbose --help` output is grepped three
times; trivial, but a single `awk` pass reads cleaner and drops forks. Same for
`sst-auth` user/password (one `IFS=: read -r sst_user sst_pass <<< ...`).

### 4.5 Dead code

- `galera-status:190,192,196-201` — commented-out old parsing loop; delete.
- `galera-status:427-436` — the `shift` statements inside `for i in "$@"` are no-ops
  (the loop iterates a pre-expanded copy and `set --` rebuilds `$@` afterwards); delete.
- `galera-status:20` — `in_node_index` is initialized twice (declaration + constant).

---

## 5. Documentation / cosmetics

1. **Node index contradiction:** README (l.27-29) and `--help` (l.46-48) both say
   *"The first node has the index 0"*, but `change_weight` rejects indices `< 1` and
   `set_weight` matches `counter+1` — the implementation is **1-based**. Fix the docs
   (or the code, but 1-based matches the on-screen `1/nodename` label).
2. Typos in README and help text: "chaning" → "changing", "hast" → "has".
3. `gray_f="${esc}[30m"` is ANSI **black**, invisible on dark-background terminals;
   bright black (gray) is `[90m`.
4. `print_commands` is drawn on terminal resize even without `--follow`
   (`update_terminal_width:398`), although the keys only work in follow mode.
5. Consider adding a `set -u`-clean pass and a small CI (GitHub Action running
   `shellcheck`) — the repo already has DeepSource configured for shell, a shellcheck
   action would catch regressions like 1.1 at PR time... though notably 1.1 *was caused
   by* mechanical lint fixing, so behavioral smoke tests (e.g. run `--help`, run against
   a throwaway MariaDB container) are worth more than more linting.

---

## Suggested priority

| # | Item | Impact |
|---|------|--------|
| 1 | 1.1 empty-arg regression | `--hosts` mode (the README's primary example) does not work at all |
| 2 | 1.2 `eval` injection | security, tool often runs as root on DB nodes |
| 3 | 1.3 / 4.1 `unsci` rewrite | wrong numbers shown exactly when the cluster is unhealthy |
| 4 | 4.2 busy loop | constant CPU + cluster query load in follow mode |
| 5 | 2.1–2.6 | correctness papercuts |
| 6 | 3.x, 4.3–4.5, 5.x | hardening, performance, polish |

# forensic-collect

The local, read-only collector for `git-forensics-agent`. It is the **only**
component that touches a repo. No npm dependencies — Node ≥ 20.

```
node forensic-collect.mjs <keygen|scan|repair|decrypt> [options]
```

## What it runs against your repos

Read-only git plumbing, enforced by an in-code allow-list:

| Purpose                | Command                          |
| ---------------------- | -------------------------------- |
| status + missing blob  | `git -C <repo> status --short`   |
| staged index           | `git -C <repo> ls-files --stage` |
| committed tree         | `git -C <repo> ls-tree -r HEAD`  |
| object store health    | `git -C <repo> fsck --no-dangling` |
| content (to encrypt)   | `git -C <repo> cat-file -p/-t`   |
| repo check             | `git -C <repo> rev-parse …`      |

The **only** write the collector can perform is `git read-tree HEAD`, and only
inside the `repair` subcommand. `reset`, `clean`, and `commit` are hard-blocked
— calling them throws *"not in the forensic command allow-list"*. This mirrors
the `git-forensics` skill invariants directly in code.

## Subcommands

### `keygen`
Prints a fresh AES-256 content key (base64url) plus a hint for saving it
`chmod 600`. **The agent never receives this key.** Lose it and any sealed
content already uploaded is unrecoverable (which is the point).

### `scan`
```
scan --case <id> --url <worker> --token <ingest> --repos a,b,c [--key <file|b64>] [--no-content]
```
Captures evidence for each repo, encrypts content locally, and POSTs the batch
to `/ingest`. Without a key (or with `--no-content`) it uploads **metadata
only** and warns you.

### `repair`
```
repair --case <id> --url <worker> --token <ingest> --repo <path>
```
1. Requests authorization (`/authorize-repair`). The agent refuses unless an
   evidence snapshot exists for that repo.
2. Prints the planned action and waits for you to type `yes`.
3. Runs `git read-tree HEAD` (rebuilds `.git/index` from HEAD; working tree
   untouched).
4. Records the confirmed (or declined) repair via `/repair-confirm`.

### `decrypt`
```
decrypt --case <id> --url <worker> --token <ingest> --id <evidenceId> --key <file|b64>
```
Fetches the opaque sealed content for one evidence record and decrypts it
**locally** with your key, so you can read a suspicious `CLAUDE.md` or staged
blob. Decryption never happens in the cloud.

## Content key options

In priority order:
1. `--key <path>` — a file containing the base64url key
2. `--key <base64url>` — the key inline
3. `FORENSIC_CONTENT_KEY` environment variable

## Running it as a tripwire (optional)

Schedule a periodic `scan` (cron / launchd / the always-on m3 node). The agent
tracks ingest freshness and raises a `collector-silent` finding if a case goes
quiet for too long — a stopped tripwire is itself a signal. The agent code is
identical whether a human runs `scan` once or a daemon posts on a schedule.

```cron
# every 30 min, scan the sovereignty-stack repos into a rolling daily case
*/30 * * * * FORENSIC_CONTENT_KEY=… node /path/forensic-collect.mjs scan \
  --case "tripwire-$(date +\%Y\%m\%d)" --url https://… --token "$INGEST_TOKEN" \
  --repos ~/Code/praxis-aegis,~/Code/secure-pride,~/Code/context-synapse
```

## Privacy

The `collectorId` reported for chain-of-custody is a SHA-256 prefix of the
hostname, not the hostname itself. Paths and object hashes are uploaded in
clear (see the main README's zero-knowledge table); file **content** is only
ever uploaded as AES-256-GCM ciphertext.

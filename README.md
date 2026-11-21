# pwned-passwords-snapshot

A fixed snapshot of the most prevalent hashes in [Pwned Passwords](https://haveibeenpwned.com/Passwords),
for blocking breached passwords offline. Each release is one file that does not change, so a build
can pin its SHA-256.

## What the file holds

- One line per hash: the SHA-1 of a password seen in public data breaches, in upper-case hex, then
  `:` and the number of times it was seen. For example `00026B85EA15A4C308623A853ECE6A5211A2F731:179049`.
- The N most prevalent hashes, ordered by count descending, then by hash ascending.
- No email addresses, usernames, sites or plaintext passwords. Every hash is already public through
  the Pwned Passwords range API.
- Compressed with zstd: `zstd -dc <file> | head`.

Each release's notes give N, the dates of the run, the SHA-256 of the file and the summary that
`snapshot.mjs` wrote.

## How it is made

Pwned Passwords no longer offers a single download, only the
[range API](https://haveibeenpwned.com/API/v3#PwnedPasswords): 1,048,576 requests, one per
five-digit SHA-1 prefix. [`snapshot.mjs`](snapshot.mjs) (Node 22, no dependencies) reads every
range, keeps the N most prevalent hashes in a bounded heap and writes them in order:

```bash
node snapshot.mjs --entries 10000000 --out top10m.txt --manifest manifest.json
zstd -19 -T0 top10m.txt -o top10m.txt.zst
```

A run checkpoints after each chunk of prefixes and resumes from the last one if it stops. The
data changes as breaches are added, so two runs on different days give different files; a release
is the result of one run.

## Licence of the data

Pwned Passwords is published by Troy Hunt. The API documentation states that the Pwned Passwords
data carries no licensing or attribution requirements.

# Is this picture really the original?

Alice draws a picture and posts it online. One week later, Bob finds a copy
of the same picture on a different website. It looks like Alice's work, but
Bob asks: *"Is this really the picture that Alice made, or did someone change
it?"*

This page shows how our tool answers that question. We use a picture because
it is easy to see. But the method is the same for any file: a program, a ZIP
file, a PDF.

## The idea in one minute

Alice has two keys:

- A **private key**. Only Alice has it. She uses it to *sign* her files.
- A **public key**. She gives it to everyone. Other people use it to *check*
  her signature.

When Alice signs `photo.png`, the tool calculates the SHA-256 hash of the
file. You can think of a hash as a fingerprint of the file. If one byte
changes, the fingerprint is completely different. The tool signs that
fingerprint with Alice's private key and writes the result to a small file,
`photo.sig.json`.

Bob gets three things:

1. the picture, `photo.png`
2. the signature, `photo.sig.json`
3. Alice's public key, from a place that he trusts (for example, Alice's own
   website)

Bob tells the tool: "I trust this key for Alice's pictures." Then he checks
the picture, and the tool gives one clear answer.

## Step 1: Alice signs her picture

This is Alice's picture:

<img src="docs/images/photo-original.png" width="300" alt="Original picture">

First, Alice makes her keys. She does this only one time:

```console
$ anticnspy keygen --algorithm ed25519 --out alice
{"algorithm": "ed25519", "keyid": "740ceb0f86f8f8d07cb30c65ec98e59033f8b6a7258f1591478737abfb7989df", "private_key": "alice.key.pem", "public_key": "alice.pub.pem"}
```

The `keyid` is the fingerprint of Alice's public key. Alice can show it on her
website, so that other people can compare it.

Then she signs the picture. She uses `alice-photos` as the package name and
the date as the version:

```console
$ anticnspy sign --file photo.png --package alice-photos --version 2026-11-16 \
    --key alice.key.pem --out photo.sig.json
Signed photo.png with ed25519 (740ceb0f...); bundle: photo.sig.json
```

Alice posts `photo.png` and `photo.sig.json` together. She keeps
`alice.key.pem` secret and does not give it to anyone.

## Step 2: Bob trusts Alice's key

Bob also does this only one time:

```console
$ anticnspy trust add --key alice.pub.pem --package alice-photos --store trust.json
{"keyid": "740ceb0f86f8f8d07cb30c65ec98e59033f8b6a7258f1591478737abfb7989df", "algorithm": "ed25519", "packages": ["alice-photos"]}
```

Bob compares this `keyid` with the one on Alice's website. They are the same,
so he knows that he has the correct key.

The `--package alice-photos` part is important. Bob trusts Alice's key
**only** for Alice's pictures. If Alice's key signs something else, Bob does
not accept it.

## Step 3: Bob checks four pictures

Bob finds four copies of `photo.png` on the internet. For each copy, he uses
the same command:

```sh
anticnspy verify --file photo.png --bundle photo.sig.json \
  --trust-store trust.json --package alice-photos --version 2026-11-16
```

### Case 1: the original

<img src="docs/images/photo-original.png" width="300" alt="Original picture">

```console
OK: Signature, trust, metadata, and artifact are valid.
```

This is Alice's picture, and not one byte is different.

### Case 2: a small brush edit

Someone opened the picture in a paint program and made a small edit. Can you
find it?

<img src="docs/images/photo-brushed.png" width="300" alt="Picture with a small red brush line">

There is a short red line on the right side, between the sleeve and the white
bird.

```console
ARTIFACT_MISMATCH: Artifact size or SHA-256 differs.
```

The edit is small, but the fingerprint is completely different:

| File | SHA-256 (first 16 characters) |
| --- | --- |
| original | `bf126c95932665df` |
| brush edit | `f8d154113b576c36` |

### Case 3: one byte changed

This copy looks exactly the same as the original:

<img src="docs/images/photo-1byte.png" width="300" alt="Picture with one changed byte">

All the pixels are the same. We changed only one letter in the hidden text
inside the PNG file: the author name `Alice` became `Alicf`. (PNG also keeps a
4-byte checksum for that text, so we updated the checksum too. If we do not
do that, some viewers do not open the file.)

```console
ARTIFACT_MISMATCH: Artifact size or SHA-256 differs.
```

The eye cannot see the change, but the fingerprint shows it:

| File | SHA-256 (first 16 characters) |
| --- | --- |
| original | `bf126c95932665df` |
| one byte | `a1b2a005dcb44f41` |

### Case 4: a fake with a fake signature

Mallory wants people to think that Alice made a different picture. A picture
without a signature looks suspicious, so Mallory makes a new key and signs the
fake picture. Mallory also uses the same package name and version:

<img src="docs/images/photo-fake.png" width="300" alt="A different picture signed by Mallory">

```console
$ anticnspy sign --file photo.png --package alice-photos --version 2026-11-16 \
    --key mallory.key.pem --out fake.sig.json
Signed photo.png with ed25519 (4bd82c28...); bundle: fake.sig.json

$ anticnspy verify --file photo.png --bundle fake.sig.json \
    --trust-store trust.json --package alice-photos --version 2026-11-16
KEY_NOT_TRUSTED: Signer is not trusted for this package.
```

The signature itself is correct. But it is from Mallory's key, and Bob does
not trust that key, so the tool stops here.

Anyone can make a key and sign a file. A signature is useful only when you
decide which keys you trust.

## Summary

| Case | What changed | Result | Exit code |
| --- | --- | --- | ---: |
| 1 | Nothing | `OK` | 0 |
| 2 | Small brush edit | `ARTIFACT_MISMATCH` | 1 |
| 3 | One letter of hidden text | `ARTIFACT_MISMATCH` | 1 |
| 4 | Different picture, signed with another key | `KEY_NOT_TRUSTED` | 1 |

The exit code is important for scripts. A script can say: "If the exit code
is not 0, stop. Do not use this file." A release pipeline uses the tool in
this way before it installs a program.

## What "original" means here

The tool tells you one thing only: **these are the exact bytes that a key you
trust signed.** Some examples:

- If Alice edits a picture and then signs it, the check gives `OK`. The
  signature shows *who* published the file, not *how* the file was made.
- If a chat app compresses Alice's picture, the bytes change. The check
  fails, even though the picture looks the same. So share the original file.
- If someone steals Alice's private key, that person can sign as Alice. Alice
  must then tell people to remove her old key (`anticnspy trust remove`).

## Try it yourself

All the files from this page are in `docs/images/`: the four pictures,
Alice's public key, Bob's trust store and both signatures. You do not need
Alice's private key to check:

```sh
cd docs/images
cp photo-brushed.png photo.png       # or photo-original.png, photo-1byte.png, photo-fake.png
anticnspy verify --file photo.png --bundle photo.sig.json \
  --trust-store trust.json --package alice-photos --version 2026-11-16
rm photo.png
```

Use `fake.sig.json` as the bundle for `photo-fake.png`.

For all commands and file formats, see the main [README](README.md).

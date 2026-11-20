# rexweb for coding agents

rexweb gives Rex panes a real WebKit browser. You drive it with the `rexweb`
command. Print this guide at any time with `rexweb skill`.

## Install

Requirements: macOS 14 or later, Rex with a working `rex` command, the Xcode
command line tools (`xcode-select -p` succeeds), and `jq`.

```sh
git clone https://github.com/acoyfellow/rexweb ~/src/rexweb
~/src/rexweb/install.sh
```

The script asks no questions and is safe to run again. It ends with
`rexweb doctor`. If it says `~/.local/bin` isn't on PATH, run
`export PATH="$HOME/.local/bin:$PATH"` or call `~/.local/bin/rexweb`.

Update with `git -C ~/src/rexweb pull && ~/src/rexweb/install.sh`. Reinstalling
restarts RexWeb, so open panes go blank for about 2 seconds and reload.

## Check it

```sh
rexweb doctor          # one line per check; exits 1 if any check fails
```

Fix each `FAIL` line as it says before you go on.

## Use it

Always keep the ID that `open` prints and pass it with `-b`. Without `-b`,
commands act on the pane someone used last, which may belong to another agent
or to the person.

```sh
id=$(rexweb open --focus=false localhost:3000) || echo "load failed: see stderr"
rexweb snapshot -b "$id"                  # numbered controls, then the page text
rexweb click -b "$id" e3                  # refs last until the next snapshot
rexweb type -b "$id" --submit e1 'hello'
rexweb wait -b "$id" --text 'Saved'
rexweb eval -b "$id" 'document.title'     # prints JSON
rexweb screenshot -b "$id" /tmp/page.png
rexweb close -b "$id"
```

- `open` prints the ID, then waits for the page. If the page fails to load, it
  still prints the ID, writes `Error: ...` to stderr, and exits 1. Close the
  pane or `nav` it again.
- `open` warns on stderr if Rex isn't showing the pane. Panes only show while
  their Rex window is on screen. `snapshot`, `eval`, and `screenshot` work
  either way. `click`, `type`, and `press` need the pane on screen. They wait
  about a second for it, then exit 1.
- `nav`, `back`, `forward`, `reload`, `click`, and `type` wait for any page
  load. `nav` and `wait` exit 1 if the page fails to load.
- `info --json` prints `{id, session, url, title, loading, visible, error}`.
  `visible` turns false for about half a second while Rex rearranges panes,
  so poll it rather than reading it once.
- Errors go to stderr as `Error: ...`, with exit status 1.

## On a remote host

If your Rex pane runs on another host (Linux included), the `rexweb` command
and RexWeb aren't there. Use `rexweb-remote`, a copy of `bin/rexweb-remote`
from this repo, which needs only `sh` and Rex:

```sh
id=$(rexweb-remote open --split=below http://myhost.example.ts.net:8000)
rexweb-remote close "$id"
```

The page loads on the person's Mac, so give an `http` or `https` URL the Mac
can reach, not `localhost`. `open` prints the block ID and returns at once; it doesn't wait
for the page or report load errors. Driving the page (`snapshot`, `click`,
`eval`, ...) works only from the Mac, with `rexweb -b ID`.

## Needs a person

These commands open a macOS dialog. Don't run them unattended:

- `rexweb links on` and `links off` (default browser confirmation)
- `rexweb cookies import` (Keychain prompt for "Chrome Safe Storage")

Passkeys and security keys don't work in rexweb. Ask the person to sign in
with Chrome and run `rexweb cookies import --domain ...`.

## When something breaks

1. Run `rexweb doctor` and fix what it reports.
2. Restart RexWeb: `pkill -x RexWeb`. Panes come back within 2 seconds.
3. Read what the pane itself says: `rex capture -b "$id"`. It prints the URL,
   or why it can't reach RexWeb.
4. If the Rex server restarted, old browser panes are now plain shells.
   Close them and open new ones.
5. Reinstall: `~/src/rexweb/install.sh`.

## How it talks

RexWeb listens on `127.0.0.1:18802`. Every request is a POST with JSON and an
`x-rexweb-token` header holding the contents of `~/.rexweb/token`. RexWeb
refuses requests from web pages. Use the CLI unless you need the raw API.

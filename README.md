# rexweb

Browser panes for [Rex](https://www.superlogical.com/rex). Each pane is a real
WebKit browser, the engine that Safari uses. It sits beside your terminal.
You and your agents can script it.

<img src="docs/hero.png" alt="A Rex window with a shell on the left running rexweb commands, and a browser pane on the right showing a to-do app on localhost:3000 that the commands just added a task to.">

## Install

You need:

- macOS 14 or later (Apple silicon or Intel).
- [Rex](https://www.superlogical.com/rex/docs/installation) with a working `rex` command. Check with `rex version`.
- The Xcode command line tools. Check with `xcode-select -p`.
- `jq`.

```sh
git clone https://github.com/acoyfellow/rexweb
cd rexweb && ./install.sh
```

The script asks no questions. It is safe to run again. It does these steps:

1. It checks the requirements. It says how to fix each one that fails.
2. It builds `RexWeb.app` into `~/Applications` and links the `rexweb` command into `~/.local/bin`.
3. It saves the path of `rex` in `~/.rexweb/config.json` as `rex_bin`.
4. It adds `require("rexweb").setup{}` to Rex's `init.lua`. It checks the file with `rex config check`. If the check fails, it restores the backup.
5. It runs `rexweb doctor`.

If `~/.local/bin` is not on your PATH, the script prints the exact line to add.

Do not share a built `RexWeb.app`. It is signed only for your Mac. Build it
from the repo.

### Update

```sh
git pull && ./install.sh
```

Reinstalling restarts RexWeb. Open panes go blank for about 2 seconds. Then
they come back.

### Uninstall

```sh
./uninstall.sh
```

If `links` is on, the script turns it off first. macOS asks you to confirm.
Then the script closes browser panes. It removes the app, the CLI, and the Lua
module. Add `--purge` to also delete `~/.rexweb` and the cookie and site data.

## Use it

Press **`Shift-Cmd-B`** in Rex, or pick **Open Browser Pane** from the command
palette. From a shell:

```sh
rexweb open localhost:3000
rexweb open docs.rs --split=below
rexweb open --tab github.com
```

Browser panes show only while their Rex window is open on screen. A browser
pane behaves like any other Rex pane. You can split it, resize it,
zoom it, move it to another tab, or close it. Its header shows the page title.

`rexweb open` prints the block ID of the new pane. Then it waits for the page
to load. If the page fails to load, it still prints the ID. It also writes
`Error: ...` to stderr and exits 1. It warns you if Rex is not showing the
pane. Use `--no-wait` to skip the wait.

| In a browser pane | |
| --- | --- |
| `Cmd-L` | Address bar |
| `Cmd-R` | Reload |
| `Shift-Cmd-R` | Reload without cache |
| `Cmd-[` / `Cmd-]` | Back / forward |
| `Cmd-+` / `Cmd--` / `Cmd-0` | Zoom |
| `Cmd-W` | Close the pane |
| `Shift-Cmd-B` | Open another browser pane beside it |
| `Cmd`-click a link | Open it in a new pane |
| `Ctrl-Opt-Arrow` | Move to the Rex pane in that direction |
| `` Ctrl-Opt-` `` | Back to Rex |

Right-click and choose **Inspect Element** for Web Inspector.

### Open Rex's links in Rex

```sh
rexweb links on
```

A person must be at the screen. macOS shows a dialog to confirm the default
browser.

Links that you click in Rex now open in a browser pane beside the pane you
clicked in. Links from other apps, and from `open` in a shell, still go to your
previous browser. RexWeb becomes your default browser. It checks where each
link came from and passes the rest on. `rexweb links off` restores your
previous browser.

## Drive it from scripts and agents

```sh
$ id=$(rexweb open --focus=false localhost:3000)
$ rexweb snapshot -b "$id"
Launch list
http://localhost:3000/

Elements:
[e1] text "New task"
[e2] button "Add"
[e3] checkbox "Write the README" [checked]

$ rexweb type -b "$id" --submit e1 'Ship it'
$ rexweb eval -b "$id" 'document.querySelector("#meta").textContent'
"2 of 4 done"
```

| Command | |
| --- | --- |
| `nav URL` | Go to a page and wait for it to load |
| `snapshot` | Number the controls on the page (`e1`, `e2`, ...) and print its text |
| `click TARGET` | Click `e2` or a CSS selector, with a real mouse click |
| `type TARGET TEXT` | Fill a field; `--clear`, `--submit` |
| `press KEY` | `enter`, `tab`, `escape`, arrows, ... |
| `eval JS` | Run JavaScript, `await` included; prints JSON |
| `wait` | Wait until `--selector` matches, `--text` appears, or the page loads |
| `screenshot [PATH]` | Save a PNG |
| `back`, `forward`, `reload`, `info`, `ls`, `focus`, `close` | |

Scripts and agents must keep the ID from `open` and pass it with `-b ID`.
Without `-b`, a command acts on the most recently used pane. That pane can
belong to someone else. `-b` also accepts an ID suffix or part of the page title. Most
commands take `--json`. `rexweb COMMAND --help` shows the rest.

`click`, `type`, and `press` need the pane on screen. If it isn't, they fail
after about a second. `snapshot`, `eval`, and `screenshot` work either way.

[AGENTS.md](AGENTS.md) is the guide for coding agents. `rexweb skill` prints
the same guide.

## Remote hosts

A Rex pane on another host, a server that the Rex app on your Mac connects to,
can open a browser pane too. Copy `bin/rexweb-remote` onto that host, somewhere
on its PATH such as `~/.local/bin`. It needs only `sh` and Rex. Then, in a
pane on that host:

```sh
id=$(rexweb-remote open http://studio.example.ts.net:3000)
rexweb-remote close "$id"
```

`open` takes `--split`, `--ratio`, `-b BLOCK`, and `--focus=true`; it leaves
focus where it is by default. The URL must be one your Mac can reach, since the
page loads there: `localhost` means the Mac.

The new pane runs on the remote host and shows the page's address as a link,
which is what Rex shows on a phone. RexWeb on the Mac follows every host in
your Rex host list, finds such panes by their terminal title, `rexweb URL`, and
draws the page over them. From the Mac, `rexweb ls` lists them with the
others, and every `rexweb` command works on them. When you browse to another
page, RexWeb writes its address back to the pane, so the link stays current
and a restarted RexWeb reopens the page you were on.

## Signing in

All browser panes share one profile. It survives restarts. You sign in to a
site once.

**Passkeys and security keys do not work.** macOS offers them only to browsers
that Apple approves. An app that you build yourself is not one of them. If your
single sign-on needs a passkey, sign in with Chrome. Then bring the session
over:

```sh
rexweb cookies import --domain example.com --domain idp.example.com --reload
```

A person must be at the screen. macOS asks for the **Chrome Safe Storage** key
in a Keychain prompt. After the import of your identity provider's session,
sites that sign in through it work until that session expires. Leave out
`--domain` to import every Chrome cookie.

Sign-in popups open in their own window. This lets them hand the result back to
the page.

## Configure

In `~/.config/rex/init.lua`:

```lua
require("rexweb").setup{
  key = "shift+cmd+b",  -- false for no shortcut
  split = "right",      -- right, left, above, or below
  ratio = 0.5,          -- the browser's share of the split
  home = "",            -- a new pane's page; empty focuses the address bar
}
```

### Layout

RexWeb reads Rex's own settings and follows them. These include the pane style
(comfortable or compact), the toolbar layout and auto-hide, the sidebar, and
the pane headers. Floating panes and full screen work too.

`~/.rexweb/config.json` has these keys:

| Key | Meaning |
| --- | --- |
| `search_url` | Search address. Use `%s` for the query. |
| `links` | `"split"` (default) or `"tab"`. |
| `fallback_browser` | Bundle ID of the browser for other links, such as `com.apple.Safari`. |
| `rex_bin` | Path of the `rex` command. `install.sh` sets it. |
| `port` | Port of the local RexWeb server. |

If a pane sits off its place, set `top`, `left`, `right`, `bottom`, `gap`,
`header`, or `radius`. Values are in points. They replace the values that
RexWeb detects.

Restart RexWeb after you edit the file: `pkill -x RexWeb`.

## Troubleshooting

- Run `rexweb doctor`. It prints one `ok` or `FAIL` line for each check. It exits 1 if any check fails. Fix each `FAIL` line as it says.
- To restart RexWeb, run `pkill -x RexWeb`. Panes come back within 2 seconds.
- If the Rex server restarts, browser panes come back as plain shells. Close them and open new ones.
- If the problem stays, run `./install.sh` again.

## How it works

<img src="docs/how-it-works.svg" alt="A Rex window holds a terminal pane running rexweb-pane. A WebKit window from RexWeb.app sits exactly over that pane's body. RexWeb.app follows the layout, and the rexweb CLI talks to it over localhost.">

Rex draws its own panes. It cannot show a web page in one. A browser pane is a
terminal pane that runs `rexweb-pane`. A borderless WebKit window from
`RexWeb.app` lies over it. RexWeb reads the layout from Rex's API and follows
it with `rex events`. It keeps each window directly above its Rex window. It
hides the window when its pane is not on screen.

RexWeb listens on 127.0.0.1 only. Every request needs the token in
`~/.rexweb/token` (mode 600). RexWeb refuses requests from web pages.

One side effect: clicking into a page makes RexWeb the active app, so Rex's
title bar dims.

## License

MIT. rexweb is a community project. Superlogical does not maintain or endorse
it. Thanks to them for Rex, and for the open API that made this possible.

#!/bin/bash
# Guard Bash against destructive or file-modifying commands in a Skyrim install.
#
# SETUP: needs jq (winget install jqlang.jq) on PATH or in the WinGet link folder, and Python 3.10+.
# No machine-specific path is written in this file.
#
# POLICY -- see the header of protect-files.sh. deny for what is never correct,
# advise for what is consequential but legitimate, ask only for what is genuinely
# the user's decision (no rule here asks since 2026-11-10).

HOOK_NAME="protect-bash"
JQ="$(command -v jq 2>/dev/null)"
[ -n "$JQ" ] || JQ="${LOCALAPPDATA//\\//}/Microsoft/WinGet/Links/jq.exe"

# MEASURED (X4 toolkit 2026-08-29, reproduced on a second machine 2026-09-06):
# `cat /dev/stdin` returns ZERO BYTES in the Claude Code hook environment, while a
# bare `cat` returns the payload. A hook that reads nothing falls through its first
# guard and exits 0 -- byte-identical to deciding "this is fine".
#
# WHY NO TEST CAUGHT IT, precisely. /dev/stdin is a symlink to /proc/self/fd/0:
# it resolves when fd 0 is a real file or an MSYS-shell pipe, and FAILS when fd 0
# is a Win32 pipe from a non-MSYS parent -- which is how Claude Code (Node) spawns
# a hook. Python's subprocess does the same, so tests/test_hooks.py DOES detect
# this on Windows and does NOT on Linux. The real reason it survived is simpler:
# nothing ran the hooks as processes at all.
INPUT=$(cat)

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)}"
BACKUP_DIR="$PROJECT_DIR/.claude/backups"
AUDIT_LOG="$BACKUP_DIR/AUDIT_LOG.txt"
HB_DIR="$BACKUP_DIR/.hook-heartbeat"

mkdir -p "$HB_DIR" 2>/dev/null

# jq is how this hook SPEAKS. If it is missing, unset, or still the literal
# unsubstituted JQ placeholder (the user extracted the zip and never ran setup.sh), then
# deny() and the inert-guard below both emit nothing -- and nothing is read as
# ALLOW. So the one refusal that must not depend on jq is printed with printf.
if ! "$JQ" --version >/dev/null 2>&1; then
    # Backslashes out, forward slashes in: this string goes into JSON by printf, not
    # through jq, and a Windows jq path (`where jq` prints one) would otherwise emit
    # invalid escapes -- unparseable output is not a deny, it is an allow.
    JQ_SHOWN="${JQ//\\//}"
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"GUARD INERT: %s cannot run jq (%s), so it evaluated NO rules and cannot report a decision. Allowing silently would be indistinguishable from approving. Install jq (winget install jqlang.jq) and run setup.sh to configure its path."}}\n' \
        "$HOOK_NAME" "$JQ_SHOWN"
    exit 0
fi
if [ -n "$INPUT" ]; then
    printf '%s payload_bytes=%s\n' "$(date +%Y%m%d_%H%M%S)" "${#INPUT}" > "$HB_DIR/protect-bash" 2>/dev/null
else
    printf '%s NO PAYLOAD\n' "$(date +%Y%m%d_%H%M%S)" > "$HB_DIR/protect-bash.blind" 2>/dev/null
fi

hooklog() { printf '[%s] protect-bash %s: %s\n' "$(date +%Y%m%d_%H%M%S)" "$1" "$2" >> "$AUDIT_LOG" 2>/dev/null; }

COMMAND=$(echo "$INPUT" | "$JQ" -r '.tool_input.command // empty')

# A Monitor watching a WebSocket runs no shell at all: tool_input has ws and no command.
if [ -z "$COMMAND" ] && [ "$(echo "$INPUT" | "$JQ" -r 'if .tool_name=="Monitor" and (.tool_input.ws|type)=="object" and (.tool_input.ws.url|type)=="string" and (.tool_input.ws.url|length)>0 and (.tool_input|has("command")|not) then "ws" else "" end')" = "ws" ]; then
    exit 0
fi

if [ -z "$COMMAND" ]; then
    hooklog REFUSE "no command in payload -- hook could not evaluate its rules"
    "$JQ" -n '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:"GUARD INERT: protect-bash.sh received no command and therefore checked NOTHING. Allowing silently would be indistinguishable from deciding this is fine. Investigate the hook payload before retrying."}}'
    exit 0
fi

deny() { hooklog DENY "$1"; "$JQ" -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'; exit 0; }
ask()  { hooklog ASK  "$1"; "$JQ" -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"ask",permissionDecisionReason:$r}}'; exit 0; }

ADVICE=""
advise() { hooklog ADVISE "$1"; ADVICE="${ADVICE:+$ADVICE | }$1"; }

# Every path pattern below accepts BOTH separators via [/\\]; see the note on the deny
# rules for why.

# --- WHERE IS THE INSTALL, ACTUALLY? ----------------------------------------
#
# The old rule asked "does this command mention a path containing the word Skyrim".
# MEASURED 2026-09-08, every one of these matched and none is the live install:
#
#   C:/Users/<user>/Projects/skyrimvr-claude-toolkit  our own repo checkout
#   .../Temp/claude/C--GOG-Games-...-Skyrim-VR/...    the session scratchpad
#   C:/Temp/skyrim-notes.txt                          a note that happens to be named
#   .../Downloads/skyrimvr-claude-toolkit-3.8.3.zip   a downloaded zip
#
# So a scratchpad cleanup was refused as "deleting the Skyrim install" -- not because
# a game path appeared elsewhere in the command, but because the scratchpad IS a game
# path to that regex. Note what this means: a shell PARSER would not have fixed it. It
# would bind the verb to its target correctly and still deny, because the target still
# matches. The defect was path RECOGNITION, not scoping.
#
# Derived from THIS FILE's location, deliberately NOT from $CLAUDE_PROJECT_DIR: the
# hooks live at <install>/.claude/hooks/, so ../.. is the install root whichever folder
# the session is rooted in. CLAUDE_PROJECT_DIR would narrow the guard to a subfolder if
# someone opened Claude Code inside Data/Scripts, and a guard that silently protects
# less than it claims is the defect this replaces.
# ⚠ Normalise the separators FIRST. `dirname` splits on `/` only, so when this hook is
# invoked by a pure-backslash path -- `bash "C:\Games\Skyrim VR\.claude\hooks\..."`,
# which is what a Windows caller passing a native path produces -- dirname finds no
# separator, returns `.`, and INSTALL_ROOT silently becomes the CURRENT WORKING
# DIRECTORY. The guard then protects whatever folder the session happens to be in and
# reports nothing wrong: it does not fail closed, because GAME_PATH is still non-empty.
# Found by a test that invoked the hook the way Python's subprocess does.
_SELF="${BASH_SOURCE[0]//\\//}"
INSTALL_ROOT="$(cd "$(dirname "$_SELF")/../.." 2>/dev/null && pwd)"
# ...and the SAME directory in its Windows spelling. `pwd` can return an MSYS MOUNT
# ALIAS -- `/tmp/...` for `C:/Users/<you>/AppData/Local/Temp/...` -- and the alias
# shares no prefix with the drive-letter form a command actually names, so the guard
# derives a root that cannot match its own install and silently allows. MEASURED: an
# install under a `/tmp`-mapped directory produced NO hook output for
# `rm -rf "C:/Users/.../Program Files (x86)"`. Both spellings are added; a root is
# only ever ADDITIVE, so naming the same directory twice costs nothing and closes the
# gap wherever MSYS aliases a mount.
INSTALL_ROOT_WIN="$(cd "$(dirname "$_SELF")/../.." 2>/dev/null && pwd -W 2>/dev/null)"

# Turn an absolute path into an ERE matching it in EITHER dialect with EITHER
# separator. PROJECT_DIR is MSYS (/c/...) under Git Bash while every path this project
# documents is Windows (C:/...), so a plain compare reads two spellings of one
# directory as two directories. Metacharacters in the path are escaped: a real install
# at "C:/Games/Skyrim (VR)" must match literally, not as a regex group.
path_to_ere() {
    local p="${1//\\//}"
    local drive="" tail="" out c i
    case "$p" in
        [a-zA-Z]:/*)  drive="${p:0:1}"; tail="${p:3}" ;;   # C:/... (Windows)
        /[a-zA-Z]/*)  drive="${p:1:1}"; tail="${p:3}" ;;   # /c/... (MSYS)
        /?*)          tail="${p:1}" ;;                     # /home/... (plain POSIX)
        *) return 1 ;;                                     # relative: not a root
    esac
    [ -n "$tail" ] || return 1
    out=""
    for (( i=0; i<${#tail}; i++ )); do
        c="${tail:i:1}"
        case "$c" in
            # ONE OR MORE separators, not exactly one. A doubled separator names the
            # identical directory on every platform, and it is not exotic -- it is how
            # you WRITE a Windows path in Python or PowerShell source:
            #   shutil.rmtree('C:\\GOG Games\\The Elder Scrolls V Skyrim VR')
            # MEASURED: with a single-character class, that spelling and
            # `rm -rf "C://GOG Games//..."` both produced NO hook output at all, which
            # the runtime reads as allow -- while the single-separator spelling denied.
            # The pre-arc rule matched with `[^"']*` and was separator-agnostic, so
            # this was a regression introduced by resolving the root, and the replay
            # evidence could not see it: 7,641 historical commands contain no doubled
            # spelling, so "0 new refusals" was silent about an entire class.
            # Braced deliberately: `$out[` reads as an array expansion to shellcheck
            # (SC1087, error severity), and this is the one place a `[` follows a
            # variable. Latent since the root-resolution rework -- CI had never run on
            # it, because the commit was never pushed.
            /)   out="${out}[/\\\\]+" ;;
            '['|']'|'*'|'+'|'?'|'^'|'$'|'('|')'|'{'|'}'|'|'|'.'|'\') out="$out\\$c" ;;
            # `GOG\ Games` (a backslash-escaped space) names the same folder (red team 2026-10-04).
            ' ') out="${out}\\\\?[[:space:]]" ;;
            *)   out="$out$c" ;;
        esac
    done
    if [ -n "$drive" ]; then
        ERE_OUT="($drive:|[/\\\\]+$drive)[/\\\\]+$out"
    else
        ERE_OUT="[/\\\\]+$out"
    fi
    return 0
}

# Paths the user configured, written by setup.sh. ADDITIVE ONLY -- INSTALL_ROOT above
# always resolves, so a missing or unreadable paths file cannot make this guard inert.
# That is the whole reason the root is derived first and the file read second: it is
# not another unsubstituted-placeholder dependency that fails silently open. (Written
# WITHOUT naming that placeholder literally: setup.sh substitutes it with a global sed,
# so a second occurrence in a COMMENT would be rewritten too, destroying the
# one-per-hook property that makes an UNCONFIGURED hook detectable at all.)
PATHS_ENV="$INSTALL_ROOT/.claude/skyrim-paths.env"
# shellcheck source=/dev/null
[ -f "$PATHS_ENV" ] && . "$PATHS_ENV" 2>/dev/null

add_root() {   # add_root VAR_VALUE -> append its ERE to $1 if new
    local val="$2" e
    [ -n "$val" ] || return 0
    path_to_ere "$val" || return 0
    e="$ERE_OUT"
    case "|${!1}|" in *"|$e|"*) return 0 ;; esac
    printf -v "$1" '%s' "${!1:+${!1}|}$e"
}

GAME_PATH=""
add_root GAME_PATH "$INSTALL_ROOT"
add_root GAME_PATH "$INSTALL_ROOT_WIN"
add_root GAME_PATH "${SKYRIM_GAME_ROOT:-}"

# The config directory lives OUTSIDE the install, so it keeps its own rule and its own
# refusal text -- the INIs there are not recoverable from a mod manager, and a reason
# that named the wrong directory would be worse than none.
CONFIG_PATH='Documents[/\\]+My Games[/\\]+Skyrim'
add_root CONFIG_PATH "${SKYRIM_CONFIG_DIR:-}"

# FAIL CLOSED. If no root could be derived, this guard evaluates nothing, and a guard
# that evaluated nothing must not answer "fine" -- that conflation is what left every
# hook in this toolkit inert for five weeks.
if [ -z "$GAME_PATH" ]; then
    hooklog REFUSE "could not derive the install root -- the delete guard evaluated NOTHING"
    "$JQ" -n '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:"GUARD INERT: protect-bash.sh could not work out which directory is the Skyrim install, so its delete rules checked NOTHING. Allowing silently would be indistinguishable from having no guard at all. Re-run setup.sh from your Skyrim folder."}}'
    exit 0
fi

# === HARD BLOCK ===
#
# DESTROYER is only the gate that starts the delete check (protect-bash-deletes.py, below): a command that names
# no delete program at all skips it. It decides nothing by itself, so it may be broad.
DESTROYER='(^|[;&|(`]|[[:space:]])(rm|rmdir|rd|ri|del|erase)[[:space:]]|Remove-Item|shutil\.rmtree|rmtree[[:space:]]*\(|[[:space:]]-delete([[:space:]]|$)|Remove-ItemProperty'
# The program word can arrive indirectly (red team 2026-10-04): `R=rm; $R -rf ...`,
# `$(echo rm)`, `` `which rm` ``, `${RM:-rm}`, `/bin/r[m]`, `r{m,m}`, `r${X}m`.
# Each spells rm next to `=`, `echo`, `which`, `:-` or a glob/brace -- caught here as text.
DESTROYER="$DESTROYER"'|(=|:-|echo[[:space:]]+|which[[:space:]]+|command[[:space:]]+-v[[:space:]]+)["'"'"']?(rm|rmdir|del|erase)([^[:alnum:]_]|$)|r\[m\]|r\{m,|r\$\{[^}]*\}m|/\?\?\?/r\?'
# A Recycle-Bin delete is still a delete (2026-10-05): the .NET FileSystem API the instructions
# recommend, and Shell.Application's MoveHere into the bin.
DESTROYER="$DESTROYER"'|Delete(File|Directory)[[:space:]]*\(|\.MoveHere[[:space:]]*\('
# 2026-11-10 review: a delete spelled through a path, quote, backslash or .exe (`/usr/bin/rm`, `"rm"`, a backslash-rm, `rm.exe`)
# never reached the delete check, which only this gate starts.
DESTROYER="$DESTROYER"'|(^|[^[:alnum:]_.-])["'"'"'\/]?(rm|rmdir|rd|ri|del|erase|unlink)(\.exe)?["'"'"']?[[:space:]]'

# Decoded text piped straight into a shell is unreadable to every rule here, so it is
# refused outright: base64 -d | bash, FromBase64String | iex, and the like.
echo "$COMMAND" | grep -qiE '(base64[[:space:]]+(-d|--decode|-D)|FromBase64String|xxd[[:space:]]+-r|openssl[[:space:]]+(base64|enc)[^|]*-d)[^|]*\|[[:space:]]*((ba|da|z|k)?sh|pwsh|powershell|iex|Invoke-Expression)([^[:alnum:]_]|$)' \
    && deny "BLOCKED: decoded text is piped into a shell, so no guard can read what it runs. Decode it to a file and run that file instead."

# Deletes are judged by what they are HANDED, resolved (user ruling 2026-11-10): protect-bash-deletes.py refuses a
# delete of the game root, Data, the config folder, a Saves folder, a backup store or the save vault, or of any folder
# holding one. The word conjunction it replaces (a delete word plus an install path anywhere in the text) refused 101
# commands in 1,602 sessions, essentially all false positives. Individual saves are covered by the save vault.
# DESTROYER stays as the cheap gate: Python starts only for commands that name a delete at all.
# The per-user Python 3.10 where it exists, else whatever python is on PATH; none at all -> exit 127 -> refused below.
DELETE_PY="${LOCALAPPDATA//\\//}/Programs/Python/Python310/python.exe"
[ -x "$DELETE_PY" ] || DELETE_PY="$(command -v python 2>/dev/null || command -v python3 2>/dev/null)"
if echo "$COMMAND" | grep -qiE "$DESTROYER"; then
    DEL_REASON=$(printf '%s' "$INPUT" | INSTALL_ROOT="$INSTALL_ROOT" INSTALL_ROOT_WIN="$INSTALL_ROOT_WIN" \
        SKYRIM_CONFIG_DIR="${SKYRIM_CONFIG_DIR:-}" SKYRIM_GAME_ROOT="${SKYRIM_GAME_ROOT:-}" \
        "$DELETE_PY" -I -B "$INSTALL_ROOT/.claude/hooks/protect-bash-deletes.py" 2>&1)
    DEL_RC=$?
    [ "$DEL_RC" -ne 0 ] && deny "BLOCKED: the delete check could not run (${DEL_REASON:0:300}). Repair .claude/hooks/protect-bash-deletes.py; do not bypass it."
    [ -n "$DEL_REASON" ] && deny "$DEL_REASON"
fi

# `reg.exe delete` is the same command as `reg delete`; the old pattern required
# whitespace immediately after `reg` and missed the .exe form entirely.
# 2026-10-03: fires only when reg / Remove-Item is the program actually RUN (same
# anchoring as the ReSaver rule below): heredoc bodies that are not fed to a shell
# are dropped and continuations joined first. The plain text match refused printf,
# grep and notes that merely MENTIONED the words, 5+ times in one session.
REG_EXEC=$(printf '%s\n' "$COMMAND" | sed -e ':a' -e '/\\$/{N;s/\\\n//;ba}' | awk '
    term != "" { t=$0; if (strip) sub(/^\t+/, "", t); if (t == term) term=""; next }
    { print
      if ($0 ~ /(^|[;&|( \t\/])(bash|sh|zsh)([ \t]+-[A-Za-z]+)*[ \t]*<</) next
      if ($0 ~ /<</ && $0 ~ /\|[ \t]*((\/usr)?\/bin\/)?(bash|sh|zsh)([ \t]|$)/) next
      l=$0; gsub(/<<</, "", l)
      if (match(l, /<<-?[ \t]*["'"'"']?[A-Za-z_][-A-Za-z0-9_]*/)) {
          h=substr(l, RSTART, RLENGTH); strip=(h ~ /^<<-/)
          gsub(/^<<-?[ \t]*["'"'"']?/, "", h); term=h } }')
REG_ANCHOR='(^|[;&|(`{!]|\$\(|(^|[[:space:]])(do|then|else|elif)[[:space:]]|(-c|-Command|eval)[[:space:]]+["'"'"']?)[[:space:]]*((sudo|exec|command)[[:space:]]+)*'
if printf '%s\n' "$REG_EXEC" | grep -qiE "${REG_ANCHOR}(cmd(\.exe)?[[:space:]]+/[cCkK][[:space:]]+[\"']?)?reg(\.exe)?[[:space:]]+delete([[:space:]]|$)" \
   || printf '%s\n' "$REG_EXEC" | grep -qiE "${REG_ANCHOR}Remove-Item(Property)?[^;&|]*Bethesda"; then
    deny "BLOCKED: Cannot delete Bethesda registry keys."
fi
# Interpreter code that SHELLS OUT to a registry delete (python -c / heredoc, node -e,
# perl -e): the anchored check above drops those bodies, so look for a process-launch
# call plus the delete words anywhere in the command. Text that only mentions the words
# without launching a process (notes, printf, grep) still passes.
if printf '%s\n' "$COMMAND" | grep -qiE '(^|[^[:alnum:]_])(python[0-9.]*|py|node|perl|ruby|pwsh|powershell)([[:space:]]|\.exe|$)' \
   && printf '%s\n' "$COMMAND" | grep -qiE '(os\.system|os\.popen|subprocess|Popen|check_output|check_call|execSync|spawnSync|child_process|system[[:space:]]*\(|Start-Process|Invoke-Expression)' \
   && printf '%s\n' "$COMMAND" | grep -qiE "reg(\.exe)?[\"',[:space:]]+delete"; then
    deny "BLOCKED: Cannot delete Bethesda registry keys."
fi

# === HARD BLOCK -- tool output aimed straight at a .psc source file ===
# .psc sources are irreplaceable. Decompilers have been observed to leave the output
# file empty when their decompilation step fails, destroying what was there.
echo "$COMMAND" | grep -qiE -- '-(o|-output|-OutputPath)\s+["'"'"']?[^"'"'"' ]*\.psc(\b|"|'"'"')' && deny "BLOCKED: Tool output cannot target a .psc file directly. Use a separate output directory."

# === HARD BLOCK -- Champollion against a .pex inside Data/Scripts/ ===
# Champollion writes to Data/Scripts/Source/ regardless of -p/-a, and on a failed
# decompile can leave the output .psc empty. This has destroyed reconstructed
# sources twice. Copy the .pex to a temp directory and run it there.
if echo "$COMMAND" | grep -qiE 'Champollion\b'; then
    echo "$COMMAND" | grep -qiE "($GAME_PATH)[/\\\\]+Data[/\\\\]+Scripts[/\\\\]+[^\"' /\\\\]+[.]pex" \
        && deny "BLOCKED: Champollion against a PEX in Data/Scripts/ has destroyed a .psc twice. Copy the .pex to a temp directory first, then run Champollion there."
fi

# === DENY -- sed in-place without binary mode ===
# Git Bash's GNU sed (4.9) opens files in TEXT mode: `sed -i` rewrites the WHOLE file with LF
# endings, every untouched line included (MEASURED 2026-10-05: a one-value edit of
# SkyrimNet.yaml turned all 117 CRLF lines into LF; the KB went the same way via Python the
# same day). Nothing reports it. `-b`/`--binary` keeps CRLF and is a no-op on LF files, so
# this costs one flag. Priced 2026-10-05 over 36,765 past commands: 234 used sed in-place,
# 2 of them with -b. With -b, a pattern ending in `$` no longer matches before a CR, so
# anchor CRLF lines with `\r$`. Short-option clusters: `-bi` has binary, `-ib` is the
# backup suffix "b" (GNU), not binary.
SED_INPLACE_NOBIN=$(printf '%s\n' "$COMMAND" | awk '
{ gsub(/[;&|]/, "\n"); n = split($0, s, "\n")
  for (k = 1; k <= n; k++) {
    seg = s[k]
    if (!match(seg, /(^|[[:space:](`])sed[[:space:]]/)) continue
    m = split(substr(seg, RSTART + RLENGTH), t, /[[:space:]]+/); inpl = 0; bin = 0
    for (j = 1; j <= m; j++) {
      w = t[j]
      if (w == "--binary") bin = 1
      else if (w ~ /^--in-place/) inpl = 1
      else if (w ~ /^-[A-Za-z]/) {
        p = index(w, "i"); pre = (p ? substr(w, 2, p - 2) : substr(w, 2))
        if (p) inpl = 1
        if (pre ~ /b/) bin = 1
      }
    }
    if (inpl && !bin) { print "x"; exit }
  } }')
[ -n "$SED_INPLACE_NOBIN" ] && deny "BLOCKED: sed in-place without -b. Git Bash sed rewrites EVERY line of the file to LF endings, silently. Use 'sed -b -i' (no-op on LF files), and end CRLF patterns with '\r\$' instead of '\$' -- or do the edit in Python on bytes."

# === ADVISE -- word-based delete/move/redirect/sed notes inside the install: REMOVED 2026-11-10 ===
# They fired on any mention of the install beside a verb (read-only and scratch work alike). Deletes of
# what cannot be restored are refused above by resolved operand; saves are covered by the save vault.

# === ADVISE -- plugin/archive/load order references ===
# Fires on a WRITE onto a plugin/archive name only: a redirect, tee/Set-Content/Out-File/-OutFile,
# or cp/mv whose destination is the plugin. The old any-mention rule was 246 of 411 advisories
# (2026-09..10), nearly all reads and tests; priced: this form fires on 12 of those 246, all writes.
PLUG_RE='[^[:space:]"'"'"';|&<>]*\.(esp|esm|esl|bsa|ba2)([^[:alnum:]_]|$)'
echo "$COMMAND" | grep -qiE ">{1,2}[[:space:]]*[\"']?$PLUG_RE|(^|[^[:alnum:]_-])(tee|Set-Content|Add-Content|Out-File)[[:space:]][^|;&]*$PLUG_RE|-OutFile[[:space:]]+[\"']?$PLUG_RE|(^|[^[:alnum:]_-])(cp|mv|copy|move|Copy-Item|Move-Item)[[:space:]][^|;&]*[[:space:]][\"']?$PLUG_RE[\"']?[[:space:]]*($|[;&|])" \
    && advise "Writing onto a plugin/archive file from the shell corrupts it. Use xelib, Spriggit or AutoMod."

# === ADVISE -- AutoMod CLI write commands ===
if echo "$COMMAND" | grep -qiE '(automod-cli\.sh|spookys-automod\.(dll|exe))["'"'"']?[[:space:]].*\b(add-weapon|add-spell|add-armor|add-npc|add-quest|add-perk|add-book|add-global|add-faction|add-leveled-item|add-form-list|add-encounter-zone|add-location|add-outfit|attach-script|set-property|auto-fill|merge|generate-seq)\b'; then
    echo "$COMMAND" | grep -qiE -- '--dry-run' || advise "AutoMod ESP write WITHOUT --dry-run. The standing rule is dry-run first, review, then write."
fi
echo "$COMMAND" | grep -qiE '(automod-cli\.sh|spookys-automod\.(dll|exe))["'"'"']?[[:space:]].*\b(replace-textures|rename-strings|fix-eyes|scale)\b' && advise "AutoMod NIF write. Cross-read the result with an independent parser before handing it to the engine -- same-tool readback misses malformed files."
echo "$COMMAND" | grep -qiE '(automod-cli\.sh|spookys-automod\.(dll|exe))["'"'"']?[[:space:]].*\b(archive\s+(create|add-files|remove-files|replace-files|update-file|merge|optimize))\b' && advise "AutoMod archive write. Loose files always override a BSA, so check for loose copies before assuming this took effect."

# === ReSaver --apply ask: REMOVED 2026-11-10 (user ruling: no pre-action save gate; the save vault keeps every
# version of the save, and ReSaver writes a NEW output beside it). ===

# === ADVISE -- any external Papyrus/ESP tool writing into the game dirs ===
if echo "$COMMAND" | grep -qiE '\b(automod|SpookysAutomod|spookys-automod|automod-cli|PapyrusAssembler|PapyrusCompiler|Champollion|Caprica|spriggit)\b'; then
    echo "$COMMAND" | grep -qiE -- "-(o|-output|-OutputPath|-p|-psc|-asm|-a)[[:space:]]+[\"']?($GAME_PATH|$CONFIG_PATH)" \
        && advise "External Papyrus/ESP tool writing into the game/data directory. Verify the output landed where you intended -- several of these have destructive defaults."
fi

[ -n "$ADVICE" ] && "$JQ" -n --arg r "$ADVICE" '{hookSpecificOutput:{hookEventName:"PreToolUse",additionalContext:$r}}'
exit 0

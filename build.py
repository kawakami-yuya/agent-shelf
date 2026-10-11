#!/usr/bin/env python3
"""Agent Shelf — Claude Code / Codex の設定・スキル・記憶などを1枚のページにまとめる。

使い方:
    python3 build.py           # 生成（初回は作業フォルダを聞かれます）
    python3 build.py --setup   # 作業フォルダの設定をやり直す

読み取りはすべてこのPCの中だけで行い、外部には一切送信しません。
APIキーやトークンらしき値は生成時に「••••••••」へ置き換えます。
生成される index.html にはあなたの設定内容が入るので、他人に渡さないでください。
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

try:  # Windows のコンソールでも日本語を出す
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
HOME = Path.home()
CLAUDE_HOME = HOME / ".claude"
CODEX_HOME = HOME / ".codex"
OUT = HERE / "index.html"
TEMPLATE = HERE / "template.html"
CONFIG = HERE / "shelf_config.json"

PRUNE_DIRS = {"node_modules", ".git", ".next", "dist", "build", ".venv", "venv", "__pycache__",
              ".vercel", ".turbo", "out", "coverage", ".cache", "worktrees", "Library"}
SKIP_NAMES = {"auth.json", ".env", ".env.local", ".env.production", ".credentials.json"}
PLUGIN_BODY_LIMIT = 0          # 追加パック（プラグイン）のスキルは本文を持たない（サイズ削減）
BODY_LIMIT = 200_000

WORKSPACES: list[Path] = []
ARCHIVE: Path | None = None
EXCLUDE: list[str] = []


def read(p: Path) -> str:
    return Path(p).read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------- 設定
def ask_path(prompt: str):
    try:
        s = input(prompt)
    except EOFError:
        return None
    s = s.strip().strip("'\"").replace("\\ ", " ")
    return Path(os.path.expanduser(s)) if s else None


def load_config(force_setup=False):
    global WORKSPACES, ARCHIVE, EXCLUDE
    cfg = {}
    if CONFIG.exists() and not force_setup:
        try:
            cfg = json.loads(read(CONFIG))
        except Exception:
            print("shelf_config.json が読めなかったので、設定なしで続けます。")
    elif sys.stdin.isatty():
        print("\n=== Agent Shelf の初期設定 ===")
        print("Claude / Codex で作業しているフォルダを教えてください（例: 仕事用フォルダ）。")
        print("フォルダをこのウィンドウにドラッグ&ドロップして Enter。複数あれば続けて入力、終わったら空のまま Enter。")
        print("※ ~/.claude と ~/.codex、最近開いたプロジェクトは指定しなくても自動で読み込みます。\n")
        ws = []
        while True:
            p = ask_path(f"作業フォルダ {len(ws)+1}（空で終了）: ")
            if not p:
                break
            if p.is_dir():
                ws.append(str(p))
            else:
                print("  → フォルダが見つかりませんでした。もう一度お試しください。")
        arc = ask_path("\n使わなくなったスキル等を置いている「保管用フォルダ」があれば（なければ空で Enter）: ")
        cfg = {"workspaces": ws, "archive": str(arc) if arc and arc.is_dir() else None, "exclude": []}
        CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n設定を保存しました（{CONFIG.name}）。やり直すときは --setup を付けて実行してください。\n")
    WORKSPACES = [Path(os.path.expanduser(w)) for w in cfg.get("workspaces", []) if Path(os.path.expanduser(w)).is_dir()]
    a = cfg.get("archive")
    ARCHIVE = Path(os.path.expanduser(a)) if a and Path(os.path.expanduser(a)).is_dir() else None
    EXCLUDE = [e for e in cfg.get("exclude", []) if e]


# ---------------------------------------------------------------- 秘匿値のマスク
SECRET_KEY_RE = re.compile(r"(token|secret|api[_-]?key|password|passwd|bearer|credential|private[_-]?key|refresh)", re.I)
INLINE_PATTERNS = [
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"(?:ntn|secret)_[A-Za-z0-9]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"EAA[A-Za-z0-9]{30,}"),
    re.compile(r"AIza[A-Za-z0-9_\-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}"),
]
ASSIGN_RE = re.compile(
    r"(?im)^(\s*[\"']?[A-Za-z0-9_\-\.]*(?:token|secret|api[_-]?key|password|passwd|client_secret|refresh)[A-Za-z0-9_\-\.]*[\"']?\s*[:=]\s*)"
    r"([\"']?)([^\s\"',#]{8,})(\2)")
MASK = "••••••••"


def redact_text(s: str) -> str:
    s = ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}", s)
    for p in INLINE_PATTERNS:
        s = p.sub(MASK, s)
    return s


def redact_json_obj(o, under_env=False):
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if (under_env or SECRET_KEY_RE.search(k)) and isinstance(v, (str, int, float)):
                out[k] = MASK
            else:
                out[k] = redact_json_obj(v, under_env=(k.lower() == "env"))
        return out
    if isinstance(o, list):
        return [redact_json_obj(v, under_env) for v in o]
    if isinstance(o, str):
        return redact_text(o)
    return o


def redact_toml(s: str) -> str:
    lines, in_env = [], False
    for line in s.splitlines():
        st = line.strip()
        if st.startswith("["):
            sec = st.strip("[]").lower()
            in_env = sec == "env" or sec.endswith(".env") or "environment" in sec
        elif "=" in st and not st.startswith("#") and (
                in_env or re.match(r"^[A-Z][A-Z0-9_]{2,}\s*=", st)):
            k = line.split("=", 1)[0]
            line = f"{k}= \"{MASK}\""
        lines.append(line)
    return redact_text("\n".join(lines))


def read_redacted(p: Path) -> str:
    raw = read(p)
    if p.suffix == ".json":
        try:
            return json.dumps(redact_json_obj(json.loads(raw)), ensure_ascii=False, indent=2)
        except Exception:
            return redact_text(raw)
    if p.suffix == ".toml":
        return redact_toml(raw)
    return redact_text(raw)


# ---------------------------------------------------------------- 解析
def parse_frontmatter(text: str):
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    block, body = text[3:end].strip("\n"), text[end + 4:].lstrip("\n")
    fm, key = {}, None
    for line in block.splitlines():
        m = re.match(r"^([A-Za-z0-9_\-]+):\s*(.*)$", line)
        if m and not line.startswith((" ", "\t")):
            key, val = m.group(1), m.group(2).strip()
            fm[key] = "" if val in (">", "|", ">-", "|-") else val.strip("\"'")
        elif key and line.strip():
            fm[key] = (fm[key] + " " + line.strip()).strip()
    return fm, body


def parse_toml_meta(text: str):
    fm = {}
    for k in ("name", "description", "model", "kind", "status", "rrule"):
        m = re.search(rf'(?m)^{k}\s*=\s*"((?:[^"\\]|\\.)*)"', text)
        if m:
            fm[k] = m.group(1)
    m = re.search(r"(?s)(?:developer_instructions|prompt)\s*=\s*(?:'''|\"\"\")(.*?)(?:'''|\"\"\")", text)
    if not m:
        m = re.search(r'(?m)^prompt\s*=\s*"((?:[^"\\]|\\.)*)"', text)
    return fm, (m.group(1).replace("\\n", "\n") if m else None)


def first_heading(body: str):
    m = re.search(r"(?m)^#{1,3}\s+(.+)$", body)
    return m.group(1).strip() if m else None


def under(p: Path, root: Path) -> bool:
    try:
        Path(p).relative_to(root)
        return True
    except ValueError:
        return False


def root_labels():
    labels = [(w, w.name) for w in WORKSPACES]
    if ARCHIVE:
        labels.append((ARCHIVE, ARCHIVE.name))
    labels.sort(key=lambda x: -len(x[0].parts))
    return labels + [(HOME, "~")]


def disp(p: Path) -> str:
    """画面表示用のパス（ホームは ~、作業フォルダはフォルダ名から）"""
    p = Path(p)
    for root, label in root_labels():
        if under(p, root):
            rel = p.relative_to(root).as_posix()
            return label if rel == "." else f"{label}/{rel}"
    return p.as_posix()


def workspace_root(p: Path) -> Path:
    parts = p.parts
    for marker in (".claude", ".agents", ".codex"):
        if marker in parts:
            return Path(*parts[:parts.index(marker)])
    return p.parent


def memory_project(p: Path) -> str:
    """~/.claude/projects/<エンコード済みパス>/memory の元フォルダ名をなるべく復元する。"""
    d = p.parts[p.parts.index("projects") + 1]
    enc = lambda q: re.sub(r"[^A-Za-z0-9]", "-", Path(q).as_posix())
    for root, label in root_labels():
        e = enc(root)
        if d.startswith(e):
            rest = d[len(e):].strip("-")
            return f"{label}/{rest}" if rest else label
    return d.strip("-") or "~"


AREA_LABEL = {
    "skills": "スキル", "agents": "サブエージェント", "scheduled-tasks": "定期タスク", "automations": "定期タスク",
    "projects": "メモリ", "memories": "メモリ", "hooks": "Hooks", "reference": "リファレンス",
    "plugins": "プラグイン", "(直下)": "設定・指示書",
}


def location_of(p: Path):
    """[グループ, 表示ラベル, 絞り込み用の接頭辞]"""
    if ARCHIVE and under(p, ARCHIVE):
        return ["archive", ARCHIVE.name, ARCHIVE.name + "/"]
    for home, g in ((CLAUDE_HOME, "claude"), (CODEX_HOME, "codex")):
        if under(p, home):
            rel = p.relative_to(home).parts
            area = rel[0] if len(rel) > 1 else "(直下)"
            prefix = disp(home) + ("/" if area == "(直下)" else f"/{area}/")
            return [g, AREA_LABEL.get(area, area), prefix]
    wr = workspace_root(p)
    d = disp(wr)
    if any(under(wr, w) for w in WORKSPACES):
        return ["workspace", d, d + "/"]
    return ["workspace", f"その他/{wr.name}", d + "/"]


def project_of(p: Path) -> str:
    if under(p, CLAUDE_HOME / "projects") and "memory" in p.parts:
        return memory_project(p)
    if under(p, CLAUDE_HOME) or under(p, CODEX_HOME):
        return "グローバル"
    loc = location_of(p)
    return loc[1]


# ---------------------------------------------------------------- 収集
items: dict = {}


def add(p: Path, kind: str, tool: str, scope: str, *, name=None, body_limit=BODY_LIMIT, extra=None):
    p = Path(p)
    if not p.is_file() or p.name in SKIP_NAMES:
        return
    key = p.as_posix()
    if key in items or any(e in key for e in EXCLUDE):
        return
    try:
        st = p.stat()
        raw = read(p)
    except OSError:
        return
    fm, body, fmt = {}, raw, "md"
    if p.suffix == ".md":
        fm, body = parse_frontmatter(raw)
    elif p.suffix == ".toml":
        fm, inner = parse_toml_meta(raw)
        fmt = "toml"
        body = inner if (inner and kind in ("agent", "task")) else raw
        if inner and kind in ("agent", "task"):
            fmt = "md"
    elif p.suffix == ".json":
        fmt = "json"
    elif p.suffix in (".sh", ".py"):
        fmt = p.suffix[1:]
    body = read_redacted(p) if fmt in ("json", "toml") else redact_text(body)
    if fm:
        fm = {k: redact_text(v) for k, v in fm.items()}
    if name is None:
        if p.name == "SKILL.md":
            name = fm.get("name") or p.parent.name
        elif p.suffix == ".toml" and fm.get("name"):
            name = fm["name"]
        else:
            name = fm.get("name") or p.stem if kind in ("agent", "memory", "reference") else p.name
    desc = fm.get("description") or ""
    if not desc and fmt == "md":
        h = first_heading(body)
        if h and h != name:
            desc = h
    trimmed = len(body) > body_limit
    items[key] = {
        "id": hashlib.sha1(key.encode()).hexdigest()[:12],
        "kind": kind, "tool": tool, "scope": scope,
        "name": name, "desc": desc[:600],
        "project": project_of(p),
        "path": disp(p), "abs": key, "uri": p.resolve().as_uri(),
        "mtime": int(st.st_mtime), "size": st.st_size,
        "lines": raw.count("\n") + 1,
        "hash": hashlib.sha1(raw.encode()).hexdigest()[:10],
        "fm": fm, "fmt": fmt, "loc": location_of(p),
        "body": (body[:body_limit] + ("\n\n…（以下省略）" if trimmed else "")) if body_limit else "",
        **(extra or {}),
    }


def walk(root: Path, max_depth=8):
    root = Path(root)
    if not root.exists():
        return
    base = len(root.parts)
    for dp, dns, fns in os.walk(root):
        depth = len(Path(dp).parts) - base
        dns[:] = [d for d in dns if d not in PRUNE_DIRS and depth < max_depth]
        for f in fns:
            yield Path(dp) / f


def classify(f: Path, scope: str):
    """作業フォルダ内のファイルを種類分けして登録する。"""
    s, n = f.as_posix(), f.name
    if n in ("CLAUDE.md", "CLAUDE.local.md"):
        add(f, "instructions", "claude", scope)
    elif n in ("AGENTS.md", "AGENT.md"):
        add(f, "instructions", "codex", scope)
    elif n == "SKILL.md" and "/.claude/skills/" in s:
        add(f, "skill", "claude", scope)
    elif n == "SKILL.md" and "/.agents/skills/" in s:
        add(f, "skill", "codex", scope)
    elif n == "SKILL.md" and "/scheduled-tasks/" in s:
        add(f, "task", "claude", scope, name=f.parent.name)
    elif n == "SKILL.md" and scope == "archive":
        add(f, "skill", "claude", scope, name=f.parent.name)
    elif n.endswith(".md") and "/.claude/agents/" in s:
        add(f, "agent", "claude", scope)
    elif n.endswith(".md") and "/.claude/commands/" in s:
        add(f, "skill", "claude", scope)
    elif n in ("settings.json", "settings.local.json") and f.parent.name == ".claude":
        add(f, "config", "claude", scope)


def recent_projects():
    """Claude Code / Codex に登録されているプロジェクトフォルダ（作業フォルダ外のもの）。"""
    out = set()
    try:
        out |= set(json.loads(read(HOME / ".claude.json")).get("projects", {}).keys())
    except Exception:
        pass
    cfg = CODEX_HOME / "config.toml"
    if cfg.exists():
        out |= set(re.findall(r'(?m)^\[projects\."([^"]+)"\]', read(cfg)))
    res = []
    for s in out:
        p = Path(s)
        if not p.is_dir() or p == HOME or "worktrees" in p.parts:
            continue
        if any(under(p, w) for w in WORKSPACES) or (ARCHIVE and under(p, ARCHIVE)):
            continue
        res.append(p)
    return sorted(res)


def collect():
    C, X = CLAUDE_HOME, CODEX_HOME

    # 全体共通のルール・設定・安全装置
    add(C / "CLAUDE.md", "instructions", "claude", "global")
    add(X / "AGENTS.md", "instructions", "codex", "global")
    for f in ("settings.json", "launch.json"):
        add(C / f, "config", "claude", "global")
    for f in ("config.toml", "hooks.json"):
        add(X / f, "config", "codex", "global")
    for d, tool in ((C / "hooks", "claude"), (X / "hooks", "codex")):
        for f in sorted(d.glob("*")) if d.exists() else []:
            add(f, "hook", tool, "global")
    for f in sorted((C / "reference").glob("*.md")):
        add(f, "reference", "claude", "global")

    # 専門スタッフ（サブエージェント）
    for f in sorted((C / "agents").glob("*.md")):
        add(f, "agent", "claude", "global")
    for f in sorted((X / "agents").glob("*.toml")):
        add(f, "agent", "codex", "global")

    # スキル
    for f in sorted((C / "skills").glob("*/SKILL.md")):
        add(f, "skill", "claude", "global")
    for f in sorted((C / "commands").glob("*.md")):
        add(f, "skill", "claude", "global")
    for f in sorted((X / "skills").glob("*/SKILL.md")):
        add(f, "skill", "codex", "global")
    for f in sorted((X / "skills/.system").glob("*/SKILL.md")):
        add(f, "skill", "codex", "system")

    # 自動タスク
    for f in sorted((C / "scheduled-tasks").glob("*/SKILL.md")):
        add(f, "task", "claude", "global", name=f.parent.name)
    for f in sorted((C / "scheduled-tasks/_archive").glob("*/SKILL.md")):
        add(f, "task", "claude", "archive", name=f.parent.name)
    for f in sorted((X / "automations").glob("*/automation.toml")):
        add(f, "task", "codex", "global")

    # 記憶メモ
    for f in sorted((C / "projects").glob("*/memory/*.md")):
        add(f, "memory", "claude", "project")
    for f in ("MEMORY.md", "memory_summary.md", "raw_memories.md"):
        add(X / "memories" / f, "memory", "codex", "global")
    for f in sorted((X / "memories").glob("*/*.md")):
        add(f, "memory", "codex", "rollout" if "rollout" in f.as_posix() else "global")

    # 作業フォルダ（設定で指定したもの・中まで探す）
    for w in WORKSPACES:
        for f in walk(w):
            if ARCHIVE and under(f, ARCHIVE):
                continue
            classify(f, "project")

    # 最近開いたプロジェクト（直下だけ見る）
    for p in recent_projects():
        for f in [p / "CLAUDE.md", p / "CLAUDE.local.md", p / "AGENTS.md",
                  p / ".claude/settings.json", p / ".claude/settings.local.json"]:
            classify(f, "project")
        for pat in (".claude/skills/*/SKILL.md", ".agents/skills/*/SKILL.md", ".claude/agents/*.md", ".claude/commands/*.md"):
            for f in sorted(p.glob(pat)):
                classify(f, "project")

    # 保管用フォルダ
    if ARCHIVE:
        for f in walk(ARCHIVE):
            if f.name in ("CLAUDE.md", "AGENTS.md", "SKILL.md"):
                classify(f, "archive")

    # 追加パック（プラグイン）のスキル：名前と説明だけ
    try:
        inst = json.loads(read(C / "plugins/installed_plugins.json")).get("plugins", {})
        for pid, entries in inst.items():
            for e in entries:
                for f in Path(e["installPath"]).glob("skills/*/SKILL.md"):
                    add(f, "plugin", "claude", "plugin", body_limit=PLUGIN_BODY_LIMIT, extra={"plugin": pid})
    except Exception:
        pass
    codex_enabled = set(re.findall(r'(?m)^\[plugins\."([^"]+)"\]\s*\nenabled\s*=\s*true', read(X / "config.toml"))) \
        if (X / "config.toml").exists() else set()
    seen_plugin = {}
    for f in sorted((X / "plugins/cache").glob("*/*/*/skills/*/SKILL.md")):
        market, plug, ver = f.parts[-6], f.parts[-5], f.parts[-4]
        pid = f"{plug}@{market}"
        if codex_enabled and pid not in codex_enabled:
            continue
        seen_plugin.setdefault(pid, ver)
        if seen_plugin[pid] != ver:  # 最初に見つかったバージョンのみ
            continue
        add(f, "plugin", "codex", "plugin", body_limit=PLUGIN_BODY_LIMIT, extra={"plugin": pid})


# ---------------------------------------------------------------- Claude ⇄ Codex の対応関係
def sync_pairs():
    by_abs = {v["abs"]: v for v in items.values()}
    pairs = []

    def pair(label, group, a: Path, b: Path):
        ia, ib = by_abs.get(Path(a).as_posix()), by_abs.get(Path(b).as_posix())
        if not ia and not ib:
            return
        if ia and ib:
            if group == "agent":
                state = "same" if (ia["desc"] == ib["desc"]) else "diff"
            else:
                state = "same" if ia["hash"] == ib["hash"] else "diff"
        else:
            state = "claude-only" if ia else "codex-only"
        pairs.append({"group": group, "label": label, "state": state,
                      "a": ia and ia["id"], "b": ib and ib["id"],
                      "am": ia and ia["mtime"], "bm": ib and ib["mtime"]})

    # スキル: <root>/.claude/skills/X ⇄ <root>/.agents/skills/X
    roots = set()
    for v in items.values():
        if v["kind"] == "skill" and v["scope"] == "project":
            m = re.match(r"(.*)/\.(claude|agents)/skills/([^/]+)/SKILL\.md$", v["abs"])
            if m:
                roots.add((m.group(1), m.group(3)))
    for root, name in sorted(roots):
        pair(f"{project_of(Path(root) / 'x')} · {name}", "skill",
             Path(root) / ".claude/skills" / name / "SKILL.md",
             Path(root) / ".agents/skills" / name / "SKILL.md")

    # ルール: CLAUDE.md ⇄ AGENTS.md（同じフォルダ）
    dirs = {Path(v["abs"]).parent.as_posix() for v in items.values()
            if v["kind"] == "instructions" and v["scope"] == "project"}
    for d in sorted(dirs):
        pair(project_of(Path(d) / "x"), "instructions", Path(d) / "CLAUDE.md", Path(d) / "AGENTS.md")

    # 専門スタッフ
    names = {Path(v["abs"]).stem for v in items.values() if v["kind"] == "agent" and v["scope"] == "global"}
    for n in sorted(names):
        pair(n, "agent", CLAUDE_HOME / "agents" / f"{n}.md", CODEX_HOME / "agents" / f"{n}.toml")
    return pairs


# ---------------------------------------------------------------- 改善の提案
TOOL_SUBS = [("Claude Code", "Codex"), ("Claude", "Codex"), ("CLAUDE.md", "AGENTS.md"), ("CLAUDE.local.md", "AGENTS.md"),
             ("/.claude/skills", "/.agents/skills"), (".claude/skills", ".agents/skills"),
             ("~/.claude", "~/.codex"), (".claude/", ".codex/"), (".Codex", ".codex")]


def normalize_tool(text: str) -> str:
    """ツール名・パスの機械的な置き換え差分を吸収する（意図的な差なので提案対象外）。"""
    for a, b in TOOL_SUBS:
        text = text.replace(a, b)
    return text


def diff_lines(a: str, b: str, limit=14):
    out = [l for l in difflib.unified_diff(a.splitlines(), b.splitlines(), "Claude", "Codex", n=0, lineterm="")
           if not l.startswith(("---", "+++", "@@"))]
    return len(out), out[:limit]


def archive_cmd(target: Path):
    return f'mv "{target}" "{ARCHIVE}/"' if ARCHIVE else None


SHORTK = {"instructions": "ルール", "skill": "スキル", "agent": "専門スタッフ", "task": "自動タスク"}


def suggestions(pairs):
    S = []
    by_id = {v["id"]: v for v in items.values()}
    live = [v for v in items.values() if v["scope"] not in ("archive", "plugin", "rollout")]
    corpus = {v["id"]: v["body"] for v in items.values() if v["scope"] != "plugin"}

    def sug(rule, pri, cat, title, reason, entries, note=""):
        if entries:
            S.append({"id": f"s{len(S)+1}", "rule": rule, "pri": pri, "cat": cat, "title": title,
                      "reason": reason, "entries": entries, "note": note})

    # 1. Claude 版と Codex 版のスキル本文のずれ
    ent = []
    for pr in pairs:
        if pr["group"] == "skill" and pr["state"] == "diff":
            a, b = by_id[pr["a"]], by_id[pr["b"]]
            n, sample = diff_lines(normalize_tool(a["body"]), normalize_tool(b["body"]))
            if n == 0:
                continue
            newer = a if a["mtime"] >= b["mtime"] else b
            side = "Claude" if newer is a else "Codex"
            ent.append({"label": pr["label"], "ids": [a["id"], b["id"]],
                        "detail": f"{n}行の差分。新しいのは {side} 側（{datetime.fromtimestamp(newer['mtime']):%m/%d}）",
                        "diff": sample})
    sug("skill_drift", "high", "同期", f"Claude と Codex でスキル本文がずれています（{len(ent)}件）",
        "同じスキルが .claude/skills と .agents/skills に二重で置かれ、片方だけ更新されています。",
        ent, "ツール名・パスの置き換えだけの差分は除外済みです。丸ごと上書きはせず、表示した差分行だけをもう片方へ反映してください（新しい側が正しいとは限りません）。")

    # 2. 片側にしかない・二重に置かれたスキル
    ent = []
    names_by_tool = {}
    for v in live:
        if v["kind"] == "skill":
            names_by_tool.setdefault((v["tool"], v["name"]), []).append(v)
    for pr in pairs:
        if pr["group"] != "skill" or not pr["state"].endswith("only"):
            continue
        v = by_id[pr["a"] or pr["b"]]
        others = [w for w in names_by_tool.get((v["tool"], v["name"]), []) if w["id"] != v["id"]]
        if others:
            w = others[0]
            ent.append({"label": pr["label"], "ids": [v["id"], w["id"]],
                        "detail": f"同じ {v['tool'].title()} 用スキルが {w['path']} にもあります。こちらは置き場所の残骸の可能性が高いです。",
                        "cmd": archive_cmd(Path(v["abs"]).parent)})
        else:
            dst_dir = ".agents" if v["tool"] == "claude" else ".claude"
            dst = v["abs"].replace("/.claude/skills/" if v["tool"] == "claude" else "/.agents/skills/", f"/{dst_dir}/skills/")
            ent.append({"label": pr["label"], "ids": [v["id"]],
                        "detail": f"{'Codex' if v['tool']=='claude' else 'Claude'} 側に対応するスキルがありません。",
                        "cmd": f'mkdir -p "{Path(dst).parent}" && cp -p "{v["abs"]}" "{dst}"'})
    sug("one_side", "high", "配置", f"片側にしかない・二重に置かれたスキル（{len(ent)}件）",
        "Claude と Codex の両方で使うスキルは、同じ場所に対で置くと管理しやすくなります。", ent)

    # 3. CLAUDE.md と AGENTS.md の二重管理
    ent = []
    for pr in pairs:
        if pr["group"] == "instructions" and pr["state"] == "diff":
            a, b = by_id[pr["a"]], by_id[pr["b"]]
            r = difflib.SequenceMatcher(None, a["body"], b["body"]).ratio()
            if r < 0.6:
                continue
            n, sample = diff_lines(normalize_tool(a["body"]), normalize_tool(b["body"]))
            if n == 0:
                continue
            ent.append({"label": pr["label"], "ids": [a["id"], b["id"]],
                        "detail": f"類似度 {r:.0%}・ツール名置換を除いた差分 {n}行（CLAUDE.md {a['lines']}行 / AGENTS.md {b['lines']}行）",
                        "diff": sample})
    sug("instr_dup", "mid", "同期", f"CLAUDE.md と AGENTS.md がほぼ同じ内容で二重管理（{len(ent)}件）",
        "共通部分は CLAUDE.md を正とし、AGENTS.md は Codex 固有の差分だけにすると更新漏れが減ります。", ent)

    # 4. Codex で開いているのに AGENTS.md がないプロジェクト
    ent = []
    cfg = CODEX_HOME / "config.toml"
    if cfg.exists():
        for proj in re.findall(r'(?m)^\[projects\."([^"]+)"\]', read(cfg)):
            d = Path(proj)
            if (d / "CLAUDE.md").exists() and not (d / "AGENTS.md").exists():
                c = items.get((d / "CLAUDE.md").as_posix())
                ent.append({"label": disp(d), "ids": [c["id"]] if c else [],
                            "detail": "Codex で使っているフォルダですが AGENTS.md がなく、CLAUDE.md のルールが Codex に届いていません。",
                            "cmd": f'cp -p "{d}/CLAUDE.md" "{d}/AGENTS.md"'})
    sug("no_agents", "mid", "配置", f"Codex で使っているのに AGENTS.md がないプロジェクト（{len(ent)}件）",
        "~/.codex/config.toml に登録されているフォルダを確認しました。", ent)

    # 5. 特定プロジェクト専用なのに共通の場所に置かれたスキル
    shared_roots = list(WORKSPACES) + [HOME]
    shared_note = "\n".join(items[(w / "CLAUDE.md").as_posix()]["body"] for w in WORKSPACES
                            if (w / "CLAUDE.md").as_posix() in items)
    proj_dirs = sorted({workspace_root(Path(v["abs"])).as_posix() for v in items.values()
                        if v["scope"] == "project" and workspace_root(Path(v["abs"])) not in shared_roots})
    proj_names = {d: Path(d).name for d in proj_dirs}
    ent = []
    for v in live:
        if v["kind"] != "skill" or v["tool"] != "claude":
            continue
        if workspace_root(Path(v["abs"])) not in shared_roots:
            continue
        if re.search(rf"{re.escape(v['name'])}[^\n]*(横断|共通)", shared_note):
            continue
        hits = {d: v["body"].count(n) for d, n in proj_names.items() if len(n) >= 4}
        hits = {d: c for d, c in hits.items() if c}
        if not hits:
            continue
        total = sum(hits.values())
        top, cnt = max(hits.items(), key=lambda x: x[1])
        if cnt >= 3 and cnt / total >= 0.8:
            ent.append({"label": v["name"], "ids": [v["id"]],
                        "detail": f"本文で {proj_names[top]} に {cnt}回言及（他プロジェクトへの言及 {total-cnt}回）。"
                                  f"{disp(Path(top))}/.claude/skills/ に移すと、そのフォルダを開いた時だけ読み込まれます。",
                        "cmd": f'mv "{Path(v["abs"]).parent}" "{top}/.claude/skills/"'})
    sug("proj_skill", "mid", "配置", f"特定プロジェクト専用に見えるスキル（{len(ent)}件）",
        "共通の場所に置いたスキルは全作業の候補一覧に並び、誤発動や選択ミスの原因になります。", ent,
        "横断で使う意図があるなら、作業フォルダ直下の CLAUDE.md にスキル名と「横断」「共通」を併記すると以後この提案から外れます。")

    # 6. 存在しないファイルへの参照
    ent = []
    home_s = HOME.as_posix()
    path_re = re.compile(r"((?:" + re.escape(home_s) + r"/|~/)[^\s`'\"()<>]+?(?:SKILL\.md|\.md|\.toml|/skills/[A-Za-z0-9_\-]+))(?=[\s`'\"()<>、。]|$)")

    def expand(m):
        return Path(m.replace("~", home_s, 1)) if m.startswith("~/") else Path(m)

    def exists_cs(pp: Path) -> bool:  # macOS / Windows は大文字小文字を区別しないので名前まで照合する
        if not pp.exists():
            return False
        try:
            return pp.name in os.listdir(pp.parent) and (pp.parent == HOME or pp.parent.name in os.listdir(pp.parent.parent))
        except OSError:
            return True

    for v in live:
        if v["kind"] not in ("task", "skill", "instructions", "agent"):
            continue
        body = v["body"].replace("Mobile Documents", "Mobile\x00Documents")  # iCloud のパスは空白を含む
        missing = sorted({m.replace("\x00", " ") for m in path_re.findall(body)
                          if not any(c in m for c in "<*{") and not exists_cs(expand(m.replace("\x00", " ")))})
        if missing:
            ent.append({"label": f"{v['name']}（{SHORTK.get(v['kind'], v['kind'])}・{'Claude' if v['tool']=='claude' else 'Codex'}）",
                        "ids": [v["id"]],
                        "detail": "存在しないパスを参照: " + " / ".join(disp(expand(m)) for m in missing[:4])
                                  + (f" ほか{len(missing)-4}件" if len(missing) > 4 else "")})
    sug("broken", "high", "参照切れ", f"存在しないファイルを参照している箇所（{len(ent)}件）",
        "移動・削除したスキルやファイルへのパスが残っており、実行時に失敗する可能性があります。", ent)

    # 7. 作業フォルダの CLAUDE.md に書かれたスキル一覧との突き合わせ
    ent = []
    for w in WORKSPACES:
        rc = items.get((w / "CLAUDE.md").as_posix())
        if not rc:
            continue
        root_skills = {v["name"]: v for v in live if v["kind"] == "skill" and v["tool"] == "claude"
                       and workspace_root(Path(v["abs"])) == w}
        mentioned = {n for n in root_skills if n in rc["body"]}
        if len(mentioned) < 3:  # 一覧を書いていないなら対象外
            continue
        for n in sorted(set(root_skills) - mentioned):
            ent.append({"label": n, "ids": [root_skills[n]["id"]],
                        "detail": f"{w.name}/.claude/skills にあるのに、{w.name}/CLAUDE.md のスキル一覧に載っていません。"})
    sug("index", "low", "索引", f"CLAUDE.md のスキル一覧と実物のずれ（{len(ent)}件）",
        "一覧は Claude がスキルを選ぶ手掛かりです。", ent)

    # 8. 同名スキルの重複
    ent = []
    groups = {}
    for v in live:
        if v["kind"] == "skill":
            groups.setdefault(v["name"], []).append(v)
    flagged = {e["label"].split(" · ")[-1] for x in S if x["cat"] == "配置" for e in x["entries"]}
    for n, vs in sorted(groups.items()):
        if n in flagged:
            continue
        roots = {(workspace_root(Path(v["abs"])).as_posix() if v["scope"] == "project" else v["tool"] + "-home") for v in vs}
        if len(roots) > 1:
            ent.append({"label": n, "ids": [v["id"] for v in vs],
                        "detail": "同名スキルが複数の場所にあります: " + " / ".join(v["path"] for v in vs)})
    sug("dup_name", "mid", "重複", f"同じ名前のスキルが複数の場所にある（{len(ent)}件）",
        "同名スキルは読み込み順でどちらが使われるかが変わります。1か所に寄せてください。", ent)

    # 9. ルールの肥大化
    ent = []
    for v in live:
        if v["kind"] == "instructions" and v["lines"] > 100:
            secs = len(re.findall(r"(?m)^## ", v["body"]))
            ent.append({"label": v["path"], "ids": [v["id"]],
                        "detail": f"{v['lines']}行・{secs}セクション。手順や資料の部分をスキルや参考資料に切り出すと毎回の読み込みが減ります。"})
    sug("size", "low", "軽量化", f"100行を超えるルール（{len(ent)}件）",
        "CLAUDE.md / AGENTS.md は毎回全文が読み込まれます。", ent)

    # 10. description 未設定
    ent = [{"label": v["name"], "ids": [v["id"]], "detail": v["path"]}
           for v in live if v["kind"] in ("skill", "agent") and v["scope"] != "system" and not v["fm"].get("description")]
    sug("nodesc", "mid", "品質", f"description が未設定のスキル・専門スタッフ（{len(ent)}件）",
        "description がないと自動選択の候補に上がりにくくなります。", ent)

    # 11. どこからも参照されず長期間更新のないスキル
    ent = []
    now = datetime.now().timestamp()
    for v in live:
        if v["kind"] != "skill" or v["scope"] == "system":
            continue
        age = (now - v["mtime"]) / 86400
        if age < 45:
            continue
        refs = sum(1 for i, b in corpus.items() if i != v["id"] and v["name"] in b and by_id[i]["name"] != v["name"])
        if refs == 0:
            ent.append({"label": v["name"], "ids": [v["id"]],
                        "detail": f"{int(age)}日更新なし・他のファイルからの参照 0件。使っていなければ保管候補です。",
                        "cmd": archive_cmd(Path(v["abs"]).parent)})
    sug("unused", "low", "整理", f"使われていない可能性があるスキル（{len(ent)}件）",
        "ルール・自動タスク・他スキルのどこにも名前が出てこないスキルです。", ent)

    # 12. 記憶メモの重複・目次もれ
    ent = []
    mem = [v for v in live if v["kind"] == "memory" and v["tool"] == "claude"]
    by_name = {}
    for v in mem:
        if Path(v["abs"]).name != "MEMORY.md":
            by_name.setdefault(Path(v["abs"]).name, []).append(v)
    for n, vs in by_name.items():
        if len(vs) > 1:
            ent.append({"label": n, "ids": [v["id"] for v in vs],
                        "detail": f"{len(vs)}プロジェクトに同名メモリ。横断的な知見なら ~/.claude/reference/ などに1本化できます。"})
    for d in sorted({Path(v["abs"]).parent for v in mem}):
        idx = items.get((d / "MEMORY.md").as_posix())
        files = {Path(v["abs"]).name for v in mem if Path(v["abs"]).parent == d} - {"MEMORY.md"}
        if idx:
            linked = set(re.findall(r"\(([^)]+\.md)\)", idx["body"]))
            for f in sorted(files - linked):
                ent.append({"label": f"{idx['project']} · {f}", "ids": [idx["id"]],
                            "detail": "メモリファイルがあるのに MEMORY.md の目次に載っておらず、思い出されません。"})
            for f in sorted(linked - files):
                ent.append({"label": f"{idx['project']} · {f}", "ids": [idx["id"]],
                            "detail": "MEMORY.md が存在しないファイルを指しています。"})
        elif files:
            ent.append({"label": project_of(d / "x"), "ids": [], "detail": "メモリはあるが MEMORY.md（目次）がありません。"})
    sug("memory", "mid", "メモリ", f"記憶メモの重複・目次もれ（{len(ent)}件）",
        "MEMORY.md に載っていないメモリは読み込まれません。", ent)

    # 13. 許可リストの肥大化
    ent = []
    for v in live:
        if v["kind"] == "config" and v["abs"].endswith("settings.local.json"):
            try:
                allow = json.loads(read(Path(v["abs"]))).get("permissions", {}).get("allow", [])
            except Exception:
                continue
            if len(allow) >= 25:
                ent.append({"label": v["project"], "ids": [v["id"]],
                            "detail": f"許可が {len(allow)}件。一度きりのコマンドが溜まっている可能性があります。"})
    sug("perms", "low", "設定", f"許可リストが膨らんでいる settings.local.json（{len(ent)}件）",
        "完全一致の許可が積み上がると見通しが悪くなります。不要分を削ると安全性も上がります。", ent)

    order = {"high": 0, "mid": 1, "low": 2}
    S.sort(key=lambda x: order[x["pri"]])
    return S


def main():
    load_config(force_setup="--setup" in sys.argv)
    collect()
    pairs = sync_pairs()
    data = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "items": sorted(items.values(), key=lambda v: (v["kind"], v["scope"], v["project"], v["name"].lower())),
        "sync": pairs,
        "suggest": suggestions(pairs),
        "roots": [w.name for w in WORKSPACES],
        "archive": ARCHIVE.name if ARCHIVE else None,
    }
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = read(TEMPLATE).replace("/*__DATA__*/null", payload)
    OUT.write_text(html, encoding="utf-8")
    try:
        os.chmod(OUT, 0o600)
    except OSError:
        pass
    kinds = {}
    for v in items.values():
        kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
    print(f"できました: {OUT}  （{len(items)}件・{OUT.stat().st_size/1024:.0f} KB）")
    print("  改善ポイント: " + str(sum(len(x["entries"]) for x in data["suggest"])) + "件")
    print("  " + ", ".join(f"{k}={n}" for k, n in sorted(kinds.items())))


if __name__ == "__main__":
    sys.exit(main())

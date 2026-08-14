#!/usr/bin/env python3
"""
mainframe_loc.py — Mainframe LOC + Purpose Fingerprint Extractor v1.0
Radiant Digital / AI-Infused Legacy Migration Practice

A companion to mainframe_scan.py. It does NOT re-implement file discovery or
classification — it imports them, so file counts reconcile with the anti-pattern
scan by construction. If FOLDER_KEYWORDS or EXT_MAP change there, this follows.

Produces ONE CSV: one row per mainframe source file, containing
  (a) a full line-of-code breakdown, and
  (b) the mechanically-extractable evidence of what the program is FOR.

It deliberately performs no inference. Everything in the output is something
the code literally says about itself. Judging purpose from that evidence is a
separate, later step.

Usage
  python mainframe_loc.py <root> [<root2> ...] [--output loc.csv] [options]

  # Two repositories in one run (a 'repo' column distinguishes them):
  python mainframe_loc.py D:\\repo1 D:\\repo2 --output estate_loc.csv

  # Same extension overrides as the scanner:
  python mainframe_loc.py D:\\src --cobol-ext .pgm,.src --copy-ext .lib

  # Quick sanity run over the first 500 files:
  python mainframe_loc.py D:\\src --limit 500

Requires mainframe_scan.py in the same directory (or on PYTHONPATH).
Python 3.7+, standard library only.
"""

import os, re, sys, csv, time, hashlib, argparse
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════════════════
# BORROWED MACHINERY — single source of truth lives in mainframe_scan.py
# ══════════════════════════════════════════════════════════════════════════════
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mainframe_scan import (
        EXTS, EXT_MAP, TYPE_LABELS, FOLDER_KEYWORDS,
        collect_files, detect_type_by_content, _folder_type,
    )
except ImportError as e:
    sys.exit(
        "ERROR: could not import from mainframe_scan.py — it must sit in the same\n"
        "       directory as this script (or on PYTHONPATH).\n"
        f"       Python said: {e}"
    )

# ══════════════════════════════════════════════════════════════════════════════
# LINE COUNTING
# ══════════════════════════════════════════════════════════════════════════════
#
# Fixed-format COBOL card layout, which drives the whole breakdown:
#   cols 1-6   sequence number area   (ignored)
#   col  7     indicator: '*' or '/' = comment, 'D' = debug, '-' = continuation
#   cols 8-11  Area A   (division/section/paragraph headers start here)
#   cols 12-72 Area B   (statements)
#   cols 73-80 identification area    (ignored)
#
# Counting rule used throughout:  blank + comment + executable == physical
# Debug lines are counted inside executable and ALSO reported separately, so
# the identity above always holds and you can subtract if you want to.

_BANNER = re.compile(r'^[\s*/=\-_.+#|]+$')


UNREADABLE = []   # (path, reason) — files that could not be opened at all


def _read_lines(path):
    """Read a file as text lines plus its raw bytes. Never raises."""
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError as e:
        # The usual cause is a cloud-only file (OneDrive / SharePoint files
        # on demand) that has never been hydrated to local disk. Silently
        # dropping these would understate the estate, so they are recorded.
        UNREADABLE.append((path, str(e)))
        return None, b''
    text = raw.decode('utf-8', errors='replace')
    # Normalise line endings; strip a trailing newline artefact
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    return lines, raw


def _is_fixed_format(lines):
    """
    Decide fixed vs free format COBOL.

    Fixed format signature: comment lines carry '*' in column 7 and there is
    content in the sequence area, or statements begin at/after column 8.
    Free format signature: '*>' inline comments, or lines beginning with '*'
    in column 1, and code starting in column 1.
    """
    col7_comments = 0
    col1_comments = 0
    col1_code = 0
    for s in lines[:400]:
        if not s.strip():
            continue
        if len(s) >= 7 and s[6] in ('*', '/'):
            col7_comments += 1
        elif s[0] in ('*', '/'):
            col1_comments += 1
        elif s[0] not in (' ', '\t'):
            col1_code += 1
    if col7_comments:
        return True
    if col1_comments or col1_code > 5:
        return False
    return True  # default: fixed, the overwhelmingly common case on z/OS


def cobol_loc(lines):
    """
    Return (counts, code_pairs) for COBOL / copybook source.

    counts     — dict of physical / blank / comment / executable / debug / continuation
    code_pairs — [(lineno, code_text)] of executable lines only, with the
                 sequence and identification areas stripped. This is what the
                 fingerprint extractors parse, so they never see comment text
                 or column-73 junk masquerading as code.
    """
    fixed = _is_fixed_format(lines)
    c = dict(physical=len(lines), blank=0, comment=0, executable=0,
             debug=0, continuation=0, fixed_format=fixed)
    code_pairs = []

    for i, s in enumerate(lines, 1):
        if not s.strip():
            c['blank'] += 1
            continue

        if fixed:
            ind = s[6] if len(s) >= 7 else ' '
            if ind in ('*', '/'):
                c['comment'] += 1
                continue
            if ind == '-':
                c['continuation'] += 1
            if ind in ('D', 'd'):
                c['debug'] += 1
            body = s[7:72] if len(s) >= 72 else (s[7:] if len(s) > 7 else '')
        else:
            t = s.lstrip()
            if t.startswith('*>') or t.startswith('*') or t.startswith('/'):
                c['comment'] += 1
                continue
            body = s.split('*>')[0]

        if not body.strip():
            # Content existed only in the sequence or identification area.
            c['blank'] += 1
            continue

        c['executable'] += 1
        code_pairs.append((i, body))

    return c, code_pairs


# Comment predicates for the non-COBOL artefact types.
_COMMENT_RULES = {
    'jcl':   lambda s: s.startswith('//*') or s.startswith('/*') and not s.startswith('//'),
    'hlasm': lambda s: s[:1] == '*' or s.lstrip().startswith('.*'),
    'bms':   lambda s: s[:1] == '*',
    'ims':   lambda s: s[:1] == '*',
    'sort':  lambda s: s[:1] == '*' or s.lstrip().startswith('*'),
    'ezt':   lambda s: s[:1] == '*',
    'nat':   lambda s: s[:1] == '*',
    'ca7':   lambda s: s[:1] == '*',
    'sql':   lambda s: s.lstrip().startswith('--'),
    'rexx':  None,   # block comments — handled specially
    'pli':   None,   # block comments — handled specially
}


def generic_loc(lines, ftype):
    """LOC breakdown for the non-COBOL artefact types."""
    c = dict(physical=len(lines), blank=0, comment=0, executable=0,
             debug=0, continuation=0, fixed_format='')
    code_pairs = []

    if ftype in ('rexx', 'pli'):
        in_block = False
        for i, s in enumerate(lines, 1):
            if not s.strip():
                c['blank'] += 1
                continue
            t = s.strip()
            if in_block:
                c['comment'] += 1
                if '*/' in t:
                    in_block = False
                continue
            if t.startswith('/*'):
                c['comment'] += 1
                if '*/' not in t[2:]:
                    in_block = True
                continue
            c['executable'] += 1
            code_pairs.append((i, s))
        return c, code_pairs

    pred = _COMMENT_RULES.get(ftype) or (lambda s: False)
    for i, s in enumerate(lines, 1):
        if not s.strip():
            c['blank'] += 1
            continue
        if pred(s):
            c['comment'] += 1
            continue
        c['executable'] += 1
        code_pairs.append((i, s))
    return c, code_pairs


# ══════════════════════════════════════════════════════════════════════════════
# PURPOSE FINGERPRINT
# ══════════════════════════════════════════════════════════════════════════════
#
# Nothing here is inferred. Each field is a verbatim extract. In descending
# order of how reliably it reveals business intent in a real estate:
#   1. Report headings and DISPLAY literals — what the program tells a human
#   2. Paragraph and section names          — the author's own decomposition
#   3. Datasets / DB2 tables / segments     — what it touches
#   4. The header comment block             — accurate when maintained, stale when not

RX_PROGRAM_ID   = re.compile(r'\bPROGRAM-ID\s*[.\s]\s*([A-Z0-9#@$-]+)', re.I)
RX_AUTHOR       = re.compile(r'\bAUTHOR\s*\.\s*(.+)', re.I)
RX_DATE_WRITTEN = re.compile(r'\bDATE-WRITTEN\s*\.\s*(.+)', re.I)
RX_PARA         = re.compile(r'^([A-Z0-9][A-Z0-9_-]{2,29})\s*\.\s*$', re.I)
RX_SECTION      = re.compile(r'^([A-Z0-9][A-Z0-9_-]{2,29})\s+SECTION\s*\.', re.I)
RX_COPY         = re.compile(r'\bCOPY\s+([A-Z0-9#@$-]+)', re.I)
RX_CALL_LIT     = re.compile(r"\bCALL\s+'([^']+)'", re.I)
RX_CALL_VAR     = re.compile(r'\bCALL\s+([A-Z][A-Z0-9-]*)\s*(?:USING|$|\.)', re.I)
RX_SELECT       = re.compile(r'\bSELECT\s+(?:OPTIONAL\s+)?([A-Z0-9-]+)', re.I)
RX_ASSIGN       = re.compile(r'\bASSIGN\s+TO\s+([A-Z0-9$#@-]+)', re.I)
RX_FD           = re.compile(r'^\s*FD\s+([A-Z0-9-]+)', re.I)
RX_SQL_TABLE    = re.compile(r'\b(?:FROM|JOIN|INTO|UPDATE)\s+([A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)?)', re.I)
RX_EXEC_SQL     = re.compile(r'\bEXEC\s+SQL\b', re.I)
RX_DLI          = re.compile(r"\bCBLTDLI\b|\bPLITDLI\b|\bAIBTDLI\b", re.I)
RX_DLI_FUNC     = re.compile(r"'(GU|GHU|GN|GHN|GNP|GHNP|ISRT|REPL|DLET|CHKP|XRST|POS)\s*'", re.I)
RX_EXEC_CICS    = re.compile(r'\bEXEC\s+CICS\b', re.I)
RX_CICS_MAP     = re.compile(r'\bMAPSET\s*\(\s*[\'"]?([A-Z0-9#@$-]+)', re.I)
RX_CICS_PGM     = re.compile(r'\b(?:XCTL|LINK)\s+PROGRAM\s*\(\s*[\'"]?([A-Z0-9#@$-]+)', re.I)
RX_CICS_TRAN    = re.compile(r'\bTRANSID\s*\(\s*[\'"]?([A-Z0-9#@$-]{1,4})', re.I)
RX_LITERAL      = re.compile(r"'([^']{8,60})'")
RX_PIC          = re.compile(r'\bPIC(?:TURE)?\s', re.I)
RX_LEVEL01      = re.compile(r'^\s*01\s+([A-Z0-9-]+)', re.I)
RX_OCCURS       = re.compile(r'\bOCCURS\b', re.I)
RX_REDEFINES    = re.compile(r'\bREDEFINES\b', re.I)

# JCL
RX_JOB   = re.compile(r'^//(\S+)\s+JOB\b', re.I)
RX_STEP  = re.compile(r'^//(\S+)\s+EXEC\b', re.I)
RX_PGM   = re.compile(r'\bEXEC\s+(?:.*,)?PGM=([A-Z0-9#@$]+)', re.I)
RX_PROC  = re.compile(r'\bEXEC\s+(?:PROC=)?([A-Z0-9#@$]+)\s*(?:,|$)', re.I)
RX_DSN   = re.compile(r'\bDSN(?:AME)?=([A-Z0-9$#@.\-()&]+)', re.I)
RX_SYSIN = re.compile(r'^//SYSIN\s+DD\s+\*', re.I)

# SQL keywords and host-variable artefacts that must never be recorded as tables.
_SQL_NOISE = {
    'SQLCA', 'SQLCODE', 'SQLSTATE', 'TABLE', 'CURSOR', 'SELECT', 'WHERE',
    'ORDER', 'GROUP', 'SET', 'VALUES', 'DUAL', 'SYSIBM', 'CURRENT', 'ONLY',
    'FETCH', 'FIRST', 'ROWS', 'WITH', 'UR', 'CS', 'RS', 'RR',
}

_NOISE_LITERALS = re.compile(
    r'^[\s\-=*_.+#|0-9]*$|^(?:Y|N|YES|NO|SPACES|ZERO|ZEROS|HIGH-VALUES|LOW-VALUES)$', re.I)


def _uniq(seq, cap):
    """Order-preserving dedupe, capped."""
    seen, out = set(), []
    for x in seq:
        k = x.upper()
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
        if len(out) >= cap:
            break
    return out


def header_comment(lines, ftype, cap_chars=800):
    """
    The leading comment block — the closest thing to documentation most
    programs have. Banner-only lines (rows of asterisks) are dropped so the
    cell holds prose rather than decoration.
    """
    out, started = [], False
    for s in lines[:120]:
        if ftype == 'jcl':
            is_c = s.startswith('//*')
            txt = s[3:].strip()
        else:
            is_c = len(s) >= 7 and s[6] in ('*', '/')
            txt = s[7:72].strip() if len(s) > 7 else ''
            if not is_c and s.lstrip()[:1] in ('*', '/') and len(s.strip()) > 1:
                is_c, txt = True, s.lstrip()[1:].strip()

        if is_c:
            started = True
            # Comment boxes are drawn with a right-hand border; strip it so the
            # cell holds the sentence rather than the decoration around it.
            txt = re.sub(r'[\s*/=\-_.+#|]+$', '', txt).strip()
            if txt and not _BANNER.match(txt):
                out.append(txt)
        elif started and s.strip():
            # First real statement after the block — stop.
            break
        if sum(len(x) for x in out) > cap_chars:
            break
    return ' | '.join(out)[:cap_chars]


def fingerprint_cobol(code_pairs, lines, ftype):
    """Extract purpose evidence from COBOL program or copybook source."""
    f = defaultdict(list)
    counts = defaultdict(int)
    in_proc = False
    in_sql = False
    pending_select = ''
    program_id = author = date_written = ''

    for ln, code in code_pairs:
        area_a = code[:4]
        stripped = code.strip()
        up = stripped.upper()

        if not program_id:
            m = RX_PROGRAM_ID.search(code)
            if m:
                program_id = m.group(1).rstrip('.').upper()
        if not author:
            m = RX_AUTHOR.search(code)
            if m:
                author = m.group(1).strip().rstrip('.')[:60]
        if not date_written:
            m = RX_DATE_WRITTEN.search(code)
            if m:
                date_written = m.group(1).strip().rstrip('.')[:40]

        if 'PROCEDURE DIVISION' in up:
            in_proc = True

        # Paragraph and section names — only when they begin in Area A.
        if area_a.strip():
            m = RX_SECTION.match(stripped)
            if m:
                f['sections'].append(m.group(1).upper())
                counts['section_count'] += 1
            elif in_proc:
                m = RX_PARA.match(stripped)
                if m and not m.group(1).upper().endswith('DIVISION'):
                    f['paragraphs'].append(m.group(1).upper())
                    counts['para_count'] += 1

        for m in RX_COPY.finditer(code):
            f['copy_members'].append(m.group(1).upper())
            counts['copy_count'] += 1
        for m in RX_CALL_LIT.finditer(code):
            f['called'].append(m.group(1).strip().upper())
            counts['called_count'] += 1
        for m in RX_CALL_VAR.finditer(code):
            f['called'].append(m.group(1).upper() + ' (dynamic)')
            counts['called_count'] += 1
        # SELECT and ASSIGN TO are conventionally written on separate cards,
        # so the file name is carried forward until its ASSIGN is found.
        m = RX_SELECT.search(code)
        if m and 'EXEC SQL' not in up and not in_proc:
            pending_select = m.group(1).upper()
        m = RX_ASSIGN.search(code)
        if m:
            ddname = m.group(1).upper()
            # Strip the organisation prefix conventions: DA-S-, UT-S-, VSAM-, AS-
            short = re.sub(r'^(?:DA|UT|UR|VS|AS|VSAM)-(?:S|I|D|A)?-?', '', ddname)
            f['datasets'].append(
                f'{pending_select}->{short}' if pending_select else short)
            counts['dataset_count'] += 1
            pending_select = ''
        m = RX_FD.match(code)
        if m:
            f['fds'].append(m.group(1).upper())

        # Table names are only harvested INSIDE an EXEC SQL ... END-EXEC block.
        # Scanning everywhere would pick up COBOL verbs that share the keywords
        # (SUBTRACT .. FROM, UNSTRING .. INTO, DIVIDE .. INTO) and fabricate tables.
        if RX_EXEC_SQL.search(code):
            counts['sql_stmt_count'] += 1
            in_sql = True
        if in_sql:
            for m in RX_SQL_TABLE.finditer(code):
                t = m.group(1).upper()
                if (t not in _SQL_NOISE and not t.startswith(':')
                        and not t.startswith('WS-') and not t.startswith('W-')):
                    f['db2_tables'].append(t)
            if 'END-EXEC' in up:
                in_sql = False

        if RX_DLI.search(code):
            counts['ims_call_count'] += 1
            for m in RX_DLI_FUNC.finditer(code):
                f['ims_funcs'].append(m.group(1).upper())

        if RX_EXEC_CICS.search(code):
            counts['cics_cmd_count'] += 1
        for m in RX_CICS_MAP.finditer(code):
            f['cics_maps'].append(m.group(1).upper())
        for m in RX_CICS_PGM.finditer(code):
            f['cics_programs'].append(m.group(1).upper())
        for m in RX_CICS_TRAN.finditer(code):
            f['cics_transids'].append(m.group(1).upper())

        # Prose literals — report headings, prompts, error messages.
        for m in RX_LITERAL.finditer(code):
            lit = m.group(1).strip()
            if len(lit) >= 8 and not _NOISE_LITERALS.match(lit) and ' ' in lit:
                f['literals'].append(lit)

        if RX_PIC.search(code):
            counts['field_count'] += 1
        if RX_LEVEL01.match(stripped):
            counts['level01_count'] += 1
        if RX_OCCURS.search(code):
            counts['occurs_count'] += 1
        if RX_REDEFINES.search(code):
            counts['redefines_count'] += 1

    return f, counts, program_id, author, date_written


def fingerprint_jcl(code_pairs):
    """Extract purpose evidence from JCL / PROC source."""
    f = defaultdict(list)
    counts = defaultdict(int)
    job_name = ''

    for ln, s in code_pairs:
        m = RX_JOB.match(s)
        if m and not job_name:
            job_name = m.group(1).upper()
        m = RX_STEP.match(s)
        if m:
            f['steps'].append(m.group(1).upper())
            counts['step_count'] += 1
        m = RX_PGM.search(s)
        if m:
            f['pgms'].append(m.group(1).upper())
            counts['pgm_count'] += 1
        elif 'EXEC' in s.upper() and 'PGM=' not in s.upper():
            m = RX_PROC.search(s.split('EXEC', 1)[-1])
            if m and m.group(1).upper() not in ('PGM',):
                f['procs'].append(m.group(1).upper())
        for m in RX_DSN.finditer(s):
            f['dsns'].append(m.group(1).upper())
            counts['dsn_count'] += 1
        if RX_SYSIN.match(s):
            counts['sysin_count'] += 1

    return f, counts, job_name


# ══════════════════════════════════════════════════════════════════════════════
# EVIDENCE SCORE
# ══════════════════════════════════════════════════════════════════════════════

def evidence_score(row):
    """
    0-100: how much self-documenting evidence this file actually yielded.

    This is the number that answers 'how hard will purpose be to establish?'
    Low scores across the estate mean purpose recovery is an SME exercise,
    not a tooling exercise — worth knowing before anyone commits to a plan.
    """
    s = 0
    if row.get('header_comment'):    s += 25
    if row.get('paragraphs'):        s += 20
    if row.get('literals'):          s += 20
    if row.get('datasets') or row.get('jcl_dsns'): s += 15
    if row.get('db2_tables'):        s += 10
    if row.get('called_programs') or row.get('jcl_pgms'): s += 10
    return min(s, 100)


# ══════════════════════════════════════════════════════════════════════════════
# PER-FILE DRIVER
# ══════════════════════════════════════════════════════════════════════════════

CSV_COLUMNS = [
    # identity
    'repo', 'relative_path', 'file_name', 'extension', 'type', 'type_label',
    'classified_by', 'size_bytes', 'sha1',
    # line counts
    'physical_lines', 'blank_lines', 'comment_lines', 'executable_lines',
    'debug_lines', 'continuation_lines', 'comment_pct', 'format',
    # program identity
    'program_id', 'author', 'date_written',
    # structure
    'section_count', 'para_count', 'paragraphs',
    'copy_count', 'copy_members',
    'called_count', 'called_programs',
    # data touched
    'dataset_count', 'datasets', 'fd_names',
    'db2_table_count', 'db2_tables', 'sql_stmt_count',
    'ims_call_count', 'ims_funcs',
    'cics_cmd_count', 'cics_maps', 'cics_programs', 'cics_transids',
    # copybook shape
    'field_count', 'level01_count', 'occurs_count', 'redefines_count',
    # jcl
    'jcl_job', 'jcl_step_count', 'jcl_steps', 'jcl_pgm_count', 'jcl_pgms',
    'jcl_procs', 'jcl_dsn_count', 'jcl_dsns', 'jcl_sysin_count',
    # purpose evidence
    'literal_count', 'literals', 'header_comment', 'evidence_score',
]

# Caps on list-valued columns. Large COBOL programs routinely carry 100+
# paragraphs, so these are set generously — recovering truncated detail later
# would mean re-reading the whole estate. Excel's hard cell limit is 32,767
# characters; 8,000 leaves ample headroom.
LIST_CAP  = 200     # max items kept in any list-valued column
CELL_CAP  = 8000    # max characters in any list-valued column


# Mainframe source frequently carries bytes that are not text: NULs from binary
# members, packed-decimal or COMP fields embedded in a copybook, EBCDIC artefacts,
# stray control characters. Written straight into a CSV these produce a file that
# Python's own csv module refuses to read back ("line contains NUL") and that
# Excel renders as mojibake. Every string leaving this script is scrubbed.
_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _clean(s):
    if not isinstance(s, str):
        return s
    if _CTRL.search(s):
        s = _CTRL.sub('', s)
    return s.replace('\r', ' ').replace('\n', ' ')


def _join(items, cap=LIST_CAP):
    return _clean('; '.join(_uniq(items, cap))[:CELL_CAP])


# ══════════════════════════════════════════════════════════════════════════════
# COBOL VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════
#
# FOLDER_KEYWORDS types every extensionless file in a matching folder by the
# folder's name alone. For 'ctc' that means every file in a CICS Transaction
# Code folder is called COBOL — including the fixed-width data and live
# input/output files that share those folders. On a real estate this inflated
# the COBOL population roughly twenty-fold and diluted every per-file metric
# built on it.
#
# PROGRAM-ID, IDENTIFICATION DIVISION and PROCEDURE DIVISION are mandatory
# structural elements of a COBOL program. Requiring one before accepting a
# folder-name verdict costs nothing — the file has already been read.

_COBOL_MARKERS = (
    'IDENTIFICATION DIVISION', 'ID DIVISION', 'PROGRAM-ID',
    'PROCEDURE DIVISION', 'ENVIRONMENT DIVISION', 'WORKING-STORAGE SECTION',
)


def looks_like_cobol(lines, scan=400):
    """True when the file carries at least one mandatory COBOL structural marker."""
    text = '\n'.join(lines[:scan]).upper()
    return any(mk in text for mk in _COBOL_MARKERS)


def looks_like_copybook(lines, scan=400):
    """A copybook has no PROGRAM-ID but does declare data: PIC clauses, 01 levels."""
    text = '\n'.join(lines[:scan]).upper()
    return bool(re.search(r'\bPIC(?:TURE)?\s', text)
                or re.search(r'^\s*(?:\d{6}.)?\s*(01|05|77)\s+[A-Z]', text, re.M))


def classification_route(path, root, emap):
    """
    Which of the scanner's three layers actually decided this file's type.

    Mirrors the priority order inside collect_files(). Recorded per file so the
    estate can be judged on how much of it rests on the weakest layer — in a
    repository with no file extensions, that distinction is the whole story.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext and ext in emap:
        return 'extension'
    if _folder_type(os.path.dirname(path), root):
        return 'folder keyword'
    return 'content detection'


def process_file(path, ftype, root, repo_name, route='', verify_cobol=False):
    lines, raw = _read_lines(path)
    if lines is None:
        return None

    # The file is already in memory, so verification is free.
    if verify_cobol and ftype == 'cobol' and not looks_like_cobol(lines):
        ftype = 'copy' if looks_like_copybook(lines) else 'data'
        route = (route or '') + ' → re-typed (no COBOL marker)'

    if ftype in ('cobol', 'copy'):
        counts, code_pairs = cobol_loc(lines)
    else:
        counts, code_pairs = generic_loc(lines, ftype)

    if ftype == 'data':
        # Counted and kept for inventory, but carries no source semantics.
        code_pairs = []

    row = {c: '' for c in CSV_COLUMNS}
    row.update({
        'repo':           repo_name,
        'relative_path':  os.path.relpath(path, root).replace('\\', '/'),
        'file_name':      os.path.basename(path),
        'extension':      os.path.splitext(path)[1].lower() or '(none)',
        'type':           ftype,
        'type_label':     TYPE_LABELS.get(ftype, 'Data / non-source'),
        'classified_by':  route,
        'size_bytes':     len(raw),
        'sha1':           hashlib.sha1(raw).hexdigest(),
        'physical_lines':     counts['physical'],
        'blank_lines':        counts['blank'],
        'comment_lines':      counts['comment'],
        'executable_lines':   counts['executable'],
        'debug_lines':        counts['debug'],
        'continuation_lines': counts['continuation'],
        'comment_pct': round(100.0 * counts['comment'] / counts['physical'], 1)
                       if counts['physical'] else 0.0,
        'format': ('fixed' if counts['fixed_format'] is True
                   else 'free' if counts['fixed_format'] is False else ''),
        'header_comment': header_comment(lines, ftype),
    })

    if ftype in ('cobol', 'copy'):
        f, c, pid, author, dw = fingerprint_cobol(code_pairs, lines, ftype)
        row.update({
            'program_id': pid, 'author': author, 'date_written': dw,
            'section_count': c['section_count'],
            'para_count':    c['para_count'],
            'paragraphs':    _join(f['paragraphs']),
            'copy_count':    c['copy_count'],
            'copy_members':  _join(f['copy_members']),
            'called_count':  c['called_count'],
            'called_programs': _join(f['called']),
            'dataset_count': c['dataset_count'],
            'datasets':      _join(f['datasets']),
            'fd_names':      _join(f['fds']),
            'db2_tables':    _join(f['db2_tables']),
            'db2_table_count': len(_uniq(f['db2_tables'], 9999)),
            'sql_stmt_count': c['sql_stmt_count'],
            'ims_call_count': c['ims_call_count'],
            'ims_funcs':     _join(f['ims_funcs'], 12),
            'cics_cmd_count': c['cics_cmd_count'],
            'cics_maps':     _join(f['cics_maps'], 20),
            'cics_programs': _join(f['cics_programs'], 20),
            'cics_transids': _join(f['cics_transids'], 20),
            'field_count':     c['field_count'],
            'level01_count':   c['level01_count'],
            'occurs_count':    c['occurs_count'],
            'redefines_count': c['redefines_count'],
            'literals':      _join(f['literals'], 25),
            'literal_count': len(_uniq(f['literals'], 9999)),
        })
    elif ftype == 'jcl':
        f, c, job = fingerprint_jcl(code_pairs)
        row.update({
            'jcl_job':         job,
            'jcl_step_count':  c['step_count'],
            'jcl_steps':       _join(f['steps']),
            'jcl_pgm_count':   c['pgm_count'],
            'jcl_pgms':        _join(f['pgms']),
            'jcl_procs':       _join(f['procs']),
            'jcl_dsn_count':   c['dsn_count'],
            'jcl_dsns':        _join(f['dsns']),
            'jcl_sysin_count': c['sysin_count'],
        })

    row['evidence_score'] = evidence_score(row)
    # Final guard: scrub every string cell, whatever produced it.
    for k, v in row.items():
        if isinstance(v, str) and v:
            row[k] = _clean(v)
    return row


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description='Mainframe LOC + purpose fingerprint extractor. '
                    'Borrows file discovery and classification from mainframe_scan.py.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument('roots', nargs='+', help='One or more repository roots')
    p.add_argument('--output', '-o', default='mainframe_loc.csv', help='Output CSV path')
    p.add_argument('--cobol-ext', default='', help='Extra COBOL extensions, comma separated')
    p.add_argument('--copy-ext',  default='', help='Extra copybook extensions')
    p.add_argument('--jcl-ext',   default='', help='Extra JCL extensions')
    p.add_argument('--types', default='', help='Restrict to these types, e.g. cobol,jcl,copy')
    p.add_argument('--verify-cobol', action='store_true',
                   help='Require a COBOL structural marker (IDENTIFICATION DIVISION, '
                        'PROGRAM-ID, PROCEDURE DIVISION) before accepting a file as '
                        'COBOL. Files failing the test are re-typed as a copybook if '
                        'they declare data, otherwise as "data" and excluded from '
                        'source metrics. Strongly recommended where FOLDER_KEYWORDS '
                        'types extensionless files by folder name alone.')
    p.add_argument('--per-file-detect', action='store_true',
                   help='Re-detect type individually for every file that reached the '
                        'content-detection fallback. mainframe_scan.py samples only the '
                        'FIRST file in such a folder and applies that verdict to all of '
                        'them, which misclassifies mixed folders. Off by default so file '
                        'counts reconcile with the anti-pattern scan; turn on for accuracy.')
    p.add_argument('--limit', type=int, default=0, help='Stop after N files (smoke test)')
    p.add_argument('--quiet', action='store_true', help='Suppress progress output')
    args = p.parse_args()

    # Extension overrides — same semantics as the scanner.
    emap = dict(EXT_MAP)
    for flag, ftype in (('cobol_ext', 'cobol'), ('copy_ext', 'copy'), ('jcl_ext', 'jcl')):
        val = getattr(args, flag)
        if val:
            for e in val.split(','):
                e = e.strip().lower()
                if e and not e.startswith('.'):
                    e = '.' + e
                emap[e] = ftype

    wanted = {t.strip().lower() for t in args.types.split(',') if t.strip()} or None

    t0 = time.time()
    all_rows = 0
    by_type = defaultdict(int)
    by_route = defaultdict(int)
    retyped = defaultdict(int)
    loc_by_type = defaultdict(int)
    skipped_total = defaultdict(int)

    out_path = args.output
    if not out_path.lower().endswith('.csv'):
        out_path += '.csv'

    with open(out_path, 'w', newline='', encoding='utf-8-sig') as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction='ignore')
        writer.writeheader()

        for root in args.roots:
            root = os.path.abspath(root)
            if not os.path.isdir(root):
                print(f'!! Not a directory, skipping: {root}', file=sys.stderr)
                continue
            repo_name = os.path.basename(root.rstrip(os.sep)) or root

            if not args.quiet:
                print(f'\n── Discovering files: {root}')
            files, skipped = collect_files(root, ext_map=emap)
            for k, v in skipped.items():
                skipped_total[k] += v

            # Record which layer decided each file, then optionally correct the
            # folder-cached content verdicts on a per-file basis.
            routes = {}
            for ftype_k, paths_k in files.items():
                for pth in paths_k:
                    routes[pth] = classification_route(pth, root, emap)

            if args.per_file_detect:
                moved = 0
                corrected = defaultdict(list)
                for ftype_k, paths_k in files.items():
                    for pth in paths_k:
                        if routes[pth] != 'content detection':
                            corrected[ftype_k].append(pth)
                            continue
                        actual = detect_type_by_content(pth) or ftype_k
                        corrected[actual].append(pth)
                        if actual != ftype_k:
                            moved += 1
                            routes[pth] = 'content detection (per-file)'
                files = corrected
                if not args.quiet:
                    print(f'   --per-file-detect: {moved:,} file(s) reclassified '
                          f'away from their folder verdict')

            total = sum(len(v) for v in files.values())
            if not args.quiet:
                print(f'   {total:,} source files classified '
                      f'({", ".join(f"{TYPE_LABELS.get(t,t)} {len(v):,}" for t, v in sorted(files.items()))})')

            n = 0
            for ftype, paths in files.items():
                if wanted and ftype not in wanted:
                    continue
                for path in paths:
                    row = process_file(path, ftype, root, repo_name,
                                       route=routes.get(path, ''),
                                       verify_cobol=args.verify_cobol)
                    if row is None:
                        continue
                    writer.writerow(row)
                    all_rows += 1
                    n += 1
                    actual = row['type']
                    if actual != ftype:
                        retyped[f'{ftype} → {actual}'] += 1
                    by_type[actual] += 1
                    loc_by_type[actual] += row['physical_lines']
                    by_route[row['classified_by']] += 1

                    if not args.quiet and n % 2000 == 0:
                        rate = n / max(time.time() - t0, 0.001)
                        print(f'   {n:,}/{total:,} files … {rate:,.0f} files/sec')
                    if args.limit and all_rows >= args.limit:
                        break
                if args.limit and all_rows >= args.limit:
                    break
            if args.limit and all_rows >= args.limit:
                break

    elapsed = time.time() - t0
    if not args.quiet:
        print(f'\n── Written: {out_path}')
        print(f'   {all_rows:,} rows in {elapsed:,.1f}s '
              f'({all_rows / max(elapsed, 0.001):,.0f} files/sec)\n')
        print(f'{"Type":<28} {"Files":>9} {"Physical LOC":>14}')
        print('─' * 54)
        for t in sorted(by_type, key=lambda x: -loc_by_type[x]):
            print(f'{TYPE_LABELS.get(t, "Data / non-source"):<28} '
                  f'{by_type[t]:>9,} {loc_by_type[t]:>14,}')
        print('─' * 54)
        print(f'{"TOTAL":<28} {all_rows:>9,} {sum(loc_by_type.values()):>14,}')

        # Source totals excluding anything verification demoted to data.
        if retyped:
            src_f = all_rows - by_type.get('data', 0)
            src_l = sum(loc_by_type.values()) - loc_by_type.get('data', 0)
            print(f'\n── --verify-cobol reclassified:')
            for k, v in sorted(retyped.items(), key=lambda x: -x[1]):
                print(f'   {k:<30} {v:>9,}')
            print(f'\n{"SOURCE ONLY (excl. data)":<28} {src_f:>9,} {src_l:>14,}')
            print(f'   {by_type.get("data", 0):,} files had no COBOL structural marker '
                  f'and are\n'
                  f'   counted as data. They remain in the CSV as type "data" so the\n'
                  f'   inventory is complete, but they are not source.')

        # How the estate was typed. In a repository with no file extensions,
        # this is the confidence statement for every number above it.
        print(f'\n{"Classified by":<28} {"Files":>9} {"Share":>9}')
        print('─' * 49)
        for r in sorted(by_route, key=lambda x: -by_route[x]):
            print(f'{r:<28} {by_route[r]:>9,} '
                  f'{100.0 * by_route[r] / max(all_rows, 1):>8.1f}%')
        cd = sum(v for k, v in by_route.items() if k.startswith('content'))
        if cd and not args.per_file_detect:
            print(f'\n   {cd:,} file(s) were typed by content detection. '
                  f'mainframe_scan.py samples\n'
                  f'   only the first file per folder and applies that verdict to the '
                  f'rest, so a\n'
                  f'   mixed folder is misclassified. Re-run with --per-file-detect '
                  f'to check.')
        if skipped_total:
            top = sorted(skipped_total.items(), key=lambda x: -x[1])[:8]
            print('\n   Unclassified (not counted): '
                  + ', '.join(f'{e} × {c:,}' for e, c in top))
            print('   If a real source extension appears above, add it with '
                  '--cobol-ext / --copy-ext / --jcl-ext.')

    # Unreadable files must never pass unnoticed — on a cloud-synced repo they
    # can be the majority, and the LOC totals would be quietly wrong.
    if UNREADABLE:
        print(f'\n!! {len(UNREADABLE):,} classified files could NOT be read and are '
              f'absent from the CSV.', file=sys.stderr)
        if any('deadlock' in r or 'Errno 11' in r or 'cloud' in r.lower()
               for _, r in UNREADABLE[:50]):
            print('   Cause looks like cloud-only files (OneDrive / SharePoint '
                  'Files On-Demand)\n'
                  '   that have never been downloaded. Make the folder '
                  '"Always keep on this device"\n'
                  '   and let it finish syncing, then re-run.', file=sys.stderr)
        for pth, reason in UNREADABLE[:5]:
            print(f'   e.g. {pth}  →  {reason}', file=sys.stderr)
        print('   (Only the CSV is written. For the full list of failures, '
              'redirect stderr: 2> failures.txt)', file=sys.stderr)


if __name__ == '__main__':
    main()

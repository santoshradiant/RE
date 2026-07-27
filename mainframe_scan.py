#!/usr/bin/env python3
"""
mainframe_scan.py — Comprehensive Mainframe Anti-Pattern Scanner v2.0
Radiant Digital / AI-Infused Legacy Migration Practice

53 anti-patterns across 13 artefact types. Fully recursive.

Artefact types:
  COBOL (.cbl .cob .cobol .cbc .cblcpy)
  JCL   (.jcl .job .proc .prc)
  Copy  (.cpy .copy .cpb .copybook)
  PL/I  (.pli .pl1 .plt)
  HLASM (.asm .mac .hlasm .assemble .s)
  REXX  (.rex .rexx .rxc)
  BMS   (.bms .map)
  IMS   (.dbd .psb)
  SQL   (.sql .ddl .dcl .dclgen)
  SORT  (.ctl .cntl .sysin)
  EZT   (.ezt .etr)
  CA7   (.jsd .sched)
  NAT   (.nat .nsp)

Usage:
  python mainframe_scan.py /path/to/source
  python mainframe_scan.py /path/to/source --output report.html

No external dependencies. Python 3.7+ standard library only.
"""

import os, re, sys, argparse
from collections import defaultdict
from datetime import datetime

# ══════════════════════════════════════════════════════════════════════════════
# FILE CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

EXTS = {
    'cobol': {'.cbl','.cob','.cobol','.cbc','.cblcpy'},
    'jcl':   {'.jcl','.job','.proc','.prc'},
    'copy':  {'.cpy','.copy','.cpb','.copybook'},
    'pli':   {'.pli','.pl1','.plt'},
    'hlasm': {'.asm','.mac','.hlasm','.assemble','.s'},
    'rexx':  {'.rex','.rexx','.rxc'},
    'bms':   {'.bms','.map'},
    'ims':   {'.dbd','.psb'},
    'sql':   {'.sql','.ddl','.dcl','.dclgen'},
    'sort':  {'.ctl','.cntl','.sysin'},
    'ezt':   {'.ezt','.etr'},
    'ca7':   {'.jsd','.sched'},
    'nat':   {'.nat','.nsp'},
}
EXT_MAP = {e: t for t, es in EXTS.items() for e in es}

TYPE_LABELS = {
    'cobol':'COBOL Programs','jcl':'JCL / PROCs','copy':'Copybooks',
    'pli':'PL/I','hlasm':'HLASM / Assembler','rexx':'REXX Scripts',
    'bms':'BMS Maps','ims':'IMS DBD/PSB','sql':'SQL / DDL / DCLGEN',
    'sort':'DFSORT Control Cards','ezt':'Easytrieve','ca7':'CA7/TWS Schedules',
    'nat':'Natural / ADABAS',
}

def collect_files(root):
    files = defaultdict(list)
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            ft = EXT_MAP.get(ext)
            if ft:
                files[ft].append(os.path.join(dirpath, fn))
    return files

# ══════════════════════════════════════════════════════════════════════════════
# PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def cobol_lines(path):
    """Yield (lineno, raw, code) — fixed-format COBOL, cols 8-72, skip comments."""
    try:
        with open(path,'r',encoding='utf-8',errors='replace') as f:
            lines = f.readlines()
    except OSError:
        return
    for i, line in enumerate(lines,1):
        s = line.rstrip('\n\r')
        if len(s) >= 7:
            ind = s[6]
            if ind in ('*','/','D','d'):
                continue
            code = s[7:72] if len(s)>=72 else s[7:]
        else:
            code = s
        yield i, s, code

def read_raw(path):
    try:
        with open(path,'r',encoding='utf-8',errors='replace') as f:
            return [(i+1, ln.rstrip()) for i,ln in enumerate(f)]
    except OSError:
        return []

def code_lines(path):
    return [(ln, code) for ln,_,code in cobol_lines(path)]

def rx_hits(lines, pat, flags=re.IGNORECASE):
    rx = re.compile(pat, flags)
    return [(ln, t.strip()) for ln,t in lines if rx.search(t)]

def extract_pid(path):
    for _,_,code in cobol_lines(path):
        m = re.match(r'\s*PROGRAM-ID\s*[.\s]\s*([A-Z0-9#@$-]+)',code,re.IGNORECASE)
        if m:
            return m.group(1).strip().rstrip('.').upper()
    return None

def F(path, lineno, snippet, detail):
    return {'file':path,'lineno':lineno,'snippet':str(snippet)[:200],'detail':detail}

# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS — AP-01 to AP-43  (COBOL / JCL / Copybook)
# ══════════════════════════════════════════════════════════════════════════════

def ap01_alter(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bALTER\b'):
            out.append(F(p,ln,s,'ALTER: paragraph jump target modified at runtime — static analysis cannot predict execution path'))
    return out

def ap02_dynamic_call(cobol):
    out=[]
    rx=re.compile(r"\bCALL\s+(?!['\"])\s*([A-Z0-9#@$-]+)",re.IGNORECASE)
    for p in cobol:
        for ln,_,code in cobol_lines(p):
            m=rx.search(code)
            if m:
                out.append(F(p,ln,code.strip(),f'Dynamic CALL to variable "{m.group(1)}" — target unknown statically'))
    return out

def _call_graph(cobol):
    g=defaultdict(set); pf={}
    for p in cobol:
        pid=extract_pid(p)
        if pid:
            pf[pid]=p
            for _,_,code in cobol_lines(p):
                m=re.search(r"\bCALL\s+['\"]([A-Z0-9#@$-]+)['\"]",code,re.IGNORECASE)
                if m: g[pid].add(m.group(1).upper())
    return g, pf

def ap03_circular_calls(cobol):
    g,pf=_call_graph(cobol)
    found=set(); out=[]; visited=set(); rec=set()
    def dfs(n,path):
        visited.add(n); rec.add(n)
        for nb in g.get(n,set()):
            if nb not in visited: dfs(nb,path+[nb])
            elif nb in rec:
                cycle=tuple(sorted(path+[nb]))
                if cycle not in found:
                    found.add(cycle)
                    cs=' → '.join(path+[nb])
                    out.append(F(pf.get(n,n),0,cs,f'Circular call chain: {cs}'))
        rec.discard(n)
    for n in list(g):
        if n not in visited: dfs(n,[n])
    return out

def ap04_orphaned(cobol,jcl):
    pids={}
    for p in cobol:
        pid=extract_pid(p)
        if pid: pids[pid]=p
    jrefs=set()
    for p in jcl:
        for _,line in read_raw(p):
            m=re.search(r'\bEXEC\s+(?:PGM=)([A-Z0-9#@$]+)',line,re.IGNORECASE)
            if m: jrefs.add(m.group(1).upper())
    crefs=set()
    for p in cobol:
        for _,_,code in cobol_lines(p):
            m=re.search(r"\bCALL\s+['\"]([A-Z0-9#@$-]+)['\"]",code,re.IGNORECASE)
            if m: crefs.add(m.group(1).upper())
    ref=jrefs|crefs
    return [F(path,0,f'PROGRAM-ID: {pid}',f'{pid} not found in JCL EXEC PGM= or CALL — likely orphaned dead code')
            for pid,path in pids.items() if pid not in ref]

def ap05_nested_copy(copy_files):
    out=[]
    for p in copy_files:
        for ln,s in rx_hits(code_lines(p),r'\bCOPY\b'):
            out.append(F(p,ln,s,'Nested COPY inside copybook — cascading hidden dependency'))
    return out

def ap06_redefines(cobol,copy_files):
    out=[]
    for p in cobol+copy_files:
        for ln,s in rx_hits(code_lines(p),r'\bREDEFINES\b'):
            out.append(F(p,ln,s,'REDEFINES: multiple data interpretations over same storage — active branch needs runtime discriminator analysis'))
    return out

def ap07_fallthrough(cobol):
    out=[]
    term=re.compile(r'\b(GO\s*TO|STOP\s+RUN|GOBACK|EXIT\s+PROGRAM|EXIT\s+PERFORM|STOP\b|EXIT\b)\b',re.IGNORECASE)
    para=re.compile(r'^([A-Z0-9#@$][A-Z0-9#@$-]*)\s*\.?\s*$',re.IGNORECASE)
    for p in cobol:
        ac=[(ln,code) for ln,_,code in cobol_lines(p) if code.strip()]
        paras=[(i,ln,c.strip().rstrip('.')) for i,(ln,c) in enumerate(ac)
               if para.match(c.strip()) and len(c.strip().split())==1]
        for pi,(ppos,pln,pname) in enumerate(paras):
            body=ac[ppos+1: paras[pi+1][0] if pi+1<len(paras) else len(ac)]
            if not body: continue
            last_ln,last_c=body[-1]
            for l2,c2 in reversed(body):
                if c2.strip(): last_ln,last_c=l2,c2.strip(); break
            if last_c and not term.search(last_c) and not last_c.endswith('.'):
                out.append(F(p,last_ln,last_c,f'Paragraph "{pname}": last statement not a terminal — control may fall through'))
    return out

def ap08_2digit_year(cobol,copy_files):
    out=[]
    name_rx=re.compile(r'\b\w*(YY|YEAR|YR|PERIOD|FISCAL|BILLING|CYCLE)\w*\b',re.IGNORECASE)
    pic_rx =re.compile(r'\bPIC\s+(?:9{2}|9\(2\)|X{2}|X\(2\))\b',re.IGNORECASE)
    pivot  =re.compile(r'\bIF\b.{0,50}\b(YY|YEAR|YR)\b.{0,30}\b(70|69|99|00|19|20)\b',re.IGNORECASE)
    for p in cobol+copy_files:
        for ln,_,code in cobol_lines(p):
            s=code.strip()
            if pic_rx.search(s) and name_rx.search(s):
                out.append(F(p,ln,s,'PIC 9(2)/X(2) date-named field — potential Y2K-style latent failure'))
            elif pivot.search(s):
                out.append(F(p,ln,s,'Year pivot comparison with fixed century cutoff — 2-digit year logic'))
    return out

def ap09_vsam_coupling(cobol,jcl):
    out=[]
    for p in cobol:
        for ln,_,code in cobol_lines(p):
            m=re.search(r'\bASSIGN\s+(?:TO\s+)?(?:DYNAMIC\s+)?([A-Z0-9#@$-]+)',code,re.IGNORECASE)
            if m:
                out.append(F(p,ln,code.strip(),f'ASSIGN to DD "{m.group(1)}" — verify file owned by this application, not cross-boundary'))
    for p in jcl:
        for ln,line in read_raw(p):
            dd=re.search(r'//\s*([A-Z0-9#@$]+)\s+DD',line,re.IGNORECASE)
            dsn=re.search(r'DSN=([^\s,]+)',line,re.IGNORECASE)
            if dd and dsn:
                out.append(F(p,ln,line.strip(),f'JCL DD "{dd.group(1)}" → DSN="{dsn.group(1)}" — check dataset ownership across application boundary'))
    return out

def ap10_db2_vsam(cobol):
    out=[]
    for p in cobol:
        has_sql=has_vsam=False; sql_ln=vsam_ln=0
        for ln,_,code in cobol_lines(p):
            if not has_sql and re.search(r'\bEXEC\s+SQL\b',code,re.IGNORECASE):
                has_sql=True; sql_ln=ln
            if not has_vsam and re.search(r'\bASSIGN\s+(?:TO\s+)?[A-Z]',code,re.IGNORECASE):
                has_vsam=True; vsam_ln=ln
        if has_sql and has_vsam:
            out.append(F(p,sql_ln,f'SQL at line {sql_ln} | VSAM at line {vsam_ln}',
                         'DB2 and VSAM in same program — no two-phase commit; partial failure leaves data inconsistent'))
    return out

def ap11_dead_flag(cobol):
    out=[]
    flag_rx=re.compile(r"\bMOVE\s+['\"]([NY0 ])['\"]?\s+TO\s+([A-Z0-9#@$-]+)",re.IGNORECASE)
    for p in cobol:
        cl=code_lines(p); flags={}; used=set()
        for ln,code in cl:
            m=flag_rx.search(code)
            if m:
                val,var=m.group(1),m.group(2).upper()
                if var not in flags: flags[var]=(ln,val,code)
            for var in list(flags):
                if re.search(rf'\bIF\b.*\b{re.escape(var)}\b',code,re.IGNORECASE): used.add(var)
                if ln!=flags[var][0] and re.search(rf'\bMOVE\b.+\bTO\s+{re.escape(var)}\b',code,re.IGNORECASE): used.add(var)
        for var,(ln,val,snip) in flags.items():
            if var not in used:
                out.append(F(p,ln,snip,f'"{var}" set to "{val}" — no conditional or reassignment found; possible hardcoded disable flag'))
    return out

def ap12_yyddd(cobol,copy_files):
    out=[]
    j_rx=re.compile(r'\b\w*(JULIAN|YYDDD|JDATE|JLNDT|JUL[-_]DATE)\w*\b',re.IGNORECASE)
    p5  =re.compile(r'\bPIC\s+9\(5\)\b',re.IGNORECASE)
    for p in cobol+copy_files:
        for ln,_,code in cobol_lines(p):
            s=code.strip()
            if j_rx.search(s):
                out.append(F(p,ln,s,'YYDDD/Julian date field name — 2-digit year + day-of-year; year-boundary arithmetic needs SME analysis'))
            elif p5.search(s):
                v=re.search(r'\b([A-Z0-9#@$-]{4,})\b',s)
                if v and any(k in v.group(1).upper() for k in ['DATE','DT','DAY','PER','PERIOD']):
                    out.append(F(p,ln,s,'PIC 9(5) date-named field — possible YYDDD format; confirm with SME'))
    return out

def ap13_commarea(cobol):
    out=[]
    for p in cobol:
        comm=[]; xctl=[]
        for ln,_,code in cobol_lines(p):
            if re.search(r'\bCOMMARE[A]?\b',code,re.IGNORECASE): comm.append(ln)
            if re.search(r'\bEXEC\s+CICS\s+XCTL\b',code,re.IGNORECASE): xctl.append(ln)
        if comm and xctl:
            for ln in xctl:
                out.append(F(p,ln,f'XCTL at {ln} | {len(comm)} COMMAREA refs',
                             'CICS XCTL + COMMAREA: field lifecycle across hop chain requires SME mapping'))
    return out

def ap14_symbolics(jcl):
    out=[]
    sym=re.compile(r'&([A-Z0-9#@$]+)(?!\.|&)',re.IGNORECASE)
    for p in jcl:
        for ln,line in read_raw(p):
            if line.startswith('//*'): continue
            syms=sym.findall(line)
            if syms:
                out.append(F(p,ln,line.strip(),f'JCL symbolic(s): {", ".join(set(syms))} — runtime value unknown without runbook or JCL execution'))
    return out

def ap15_dfsort(jcl):
    out=[]
    srx=re.compile(r'\bEXEC\b.*\bPGM=(DFSORT|SORT|ICETOOL|IEBGENER|SYNCSORT)\b',re.IGNORECASE)
    lrx=re.compile(r'\b(INCLUDE|OMIT|SUM|OUTREC|INREC|OUTFIL|JOINKEYS|OVERLAY|REFORMAT)\b',re.IGNORECASE)
    for p in jcl:
        in_sort=False
        for ln,line in read_raw(p):
            if srx.search(line): in_sort=True
            if in_sort and re.search(r'^//\S+\s+EXEC\b',line) and not srx.search(line): in_sort=False
            if in_sort and lrx.search(line):
                out.append(F(p,ln,line.strip(),'DFSORT control statement with embedded business logic — CAST does not parse; must be manually extracted'))
    return out

def ap16_proc_override(jcl):
    out=[]
    for p in jcl:
        is_proc=False
        for ln,line in read_raw(p):
            if re.search(r'^\s*//\s*\S+\s+PROC\b',line,re.IGNORECASE): is_proc=True
            m=re.search(r'^\s*//\s*SET\s+([A-Z0-9]+)=',line,re.IGNORECASE)
            if is_proc and m:
                out.append(F(p,ln,line.strip(),f'PROC SET {m.group(1)}= — symbolic default; invoking job may override at runtime'))
    return out

def ap17_odo(cobol,copy_files):
    out=[]
    for p in cobol+copy_files:
        for ln,s in rx_hits(code_lines(p),r'\bOCCURS\b.*\bDEPENDING\b'):
            out.append(F(p,ln,s,'OCCURS DEPENDING ON: variable-length array — Cobrix and schema tools assume fixed layout; record offsets shift per row; silent schema mismatch on every affected field'))
    return out

def ap18_copy_replacing(cobol,copy_files):
    out=[]
    for p in cobol+copy_files:
        for ln,s in rx_hits(code_lines(p),r'\bCOPY\b.*\bREPLACING\b'):
            out.append(F(p,ln,s,'COPY REPLACING: field names generated at compile time — raw copybook contains placeholder tokens, not actual names; schema mapping tools read wrong field names'))
    return out

def ap19_comp12(cobol,copy_files):
    out=[]
    for p in cobol+copy_files:
        for ln,s in rx_hits(code_lines(p),r'\bCOMP-[12]\b|\bCOMPUTATIONAL-[12]\b'):
            out.append(F(p,ln,s,'COMP-1/COMP-2 (IEEE 754 binary float): mixed with COMP-3 packed decimal in arithmetic — Python Decimal does not replicate COBOL float/decimal interleaved rounding'))
    return out

def ap20_sign_separate(cobol,copy_files):
    out=[]
    for p in cobol+copy_files:
        for ln,s in rx_hits(code_lines(p),r'\bSIGN\s+IS\s+(LEADING|TRAILING)\s+SEPARATE\b'):
            out.append(F(p,ln,s,'SIGN IS SEPARATE: explicit sign character (non-default EBCDIC overpunch) — Cobrix must be told encoding explicitly or every signed field reads wrong'))
    return out

def ap21_external_global(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bIS\s+(EXTERNAL|GLOBAL)\b'):
            out.append(F(p,ln,s,'EXTERNAL/GLOBAL: data shared across programs without CALL — implicit coupling invisible to call-graph analysis'))
    return out

def ap22_entry_points(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r"^\s*ENTRY\s+['\"]"):
            out.append(F(p,ln,s,'Alternate ENTRY point: same compiled program callable by different name with different LINKAGE SECTION layout — translation must handle each entry contract separately'))
    return out

def ap23_declaratives(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'^\s*DECLARATIVES\b'):
            out.append(F(p,ln,s,'DECLARATIVES section: I/O error handlers activated by runtime condition mechanism, not a callable paragraph — almost universally missed in automated translation'))
    return out

def ap24_88_through(cobol,copy_files):
    out=[]
    for p in cobol+copy_files:
        for ln,s in rx_hits(code_lines(p),r'^\s*88\b.*\b(THROUGH|THRU)\b'):
            out.append(F(p,ln,s,'Level-88 THROUGH range: multi-value condition covering an inclusive numeric range — Python translation must replicate range logic, not just an explicit list'))
    return out

def ap25_size_error(cobol):
    out=[]
    for p in cobol:
        for ln,_,code in cobol_lines(p):
            s=code.strip()
            if re.search(r'\bON\s+SIZE\s+ERROR\b',s,re.IGNORECASE):
                out.append(F(p,ln,s,'ON SIZE ERROR: developer anticipated arithmetic overflow — handler must be translated; if omitted, overflow silently truncates'))
            elif re.search(r'\bROUNDED\b',s,re.IGNORECASE) and re.search(r'\b(COMPUTE|ADD|SUBTRACT|MULTIPLY|DIVIDE)\b',s,re.IGNORECASE):
                out.append(F(p,ln,s,'ROUNDED clause: COBOL applies half-up rounding by default — Python Decimal must be configured with identical rounding mode'))
    return out

def ap26_sort_verb(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'^\s*(SORT|MERGE)\s+\S'):
            out.append(F(p,ln,s,'Internal COBOL SORT/MERGE: sort keys, INPUT PROCEDURE, and OUTPUT PROCEDURE define business logic inline — Spark equivalent must replicate key sequence and filter logic exactly'))
    return out

def ap27_string_unstring(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'^\s*(STRING|UNSTRING)\b'):
            out.append(F(p,ln,s,'STRING/UNSTRING: character manipulation using EBCDIC byte positions and delimiters — Python string operations use Unicode; collation and delimiter bytes differ'))
    return out

def ap28_inspect(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'^\s*INSPECT\b'):
            out.append(F(p,ln,s,'INSPECT TALLYING/REPLACING: character-by-character operation using EBCDIC byte values — transliteration targets and replacements are EBCDIC-specific'))
    return out

def ap29_xml_json(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\b(XML|JSON)\s+(GENERATE|PARSE)\b'):
            out.append(F(p,ln,s,'XML/JSON GENERATE/PARSE verb (COBOL 2002+): many transpilers do not handle this; verify translator supports the feature or replace with explicit library calls'))
    return out

def ap30_write_advancing(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bWRITE\b.*\bADVANCING\b'):
            out.append(F(p,ln,s,'WRITE ADVANCING: ASA carriage control byte in output — downstream consumers (print servers, batch jobs) may depend on these control characters; Python write must replicate format'))
    return out

def ap31_dynamic_sql(cobol):
    out=[]
    for p in cobol:
        for ln,_,code in cobol_lines(p):
            if re.search(r'\bEXEC\s+SQL\b',code,re.IGNORECASE) and re.search(r'\b(PREPARE|EXECUTE\s+IMMEDIATE)\b',code,re.IGNORECASE):
                out.append(F(p,ln,code.strip(),'Dynamic SQL PREPARE/EXECUTE: runtime-constructed query — full table and column access set cannot be determined statically; parity test cannot exercise all paths'))
    return out

def ap32_sql_whenever(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bEXEC\s+SQL\s+WHENEVER\b'):
            out.append(F(p,ln,s,'EXEC SQL WHENEVER: implicit GO TO injected after every subsequent SQL call — translated code must replicate this error dispatch at every SQL call site or error handling is silently dropped'))
    return out

def ap33_pseudo_conv(cobol):
    out=[]
    for p in cobol:
        for ln,_,code in cobol_lines(p):
            if re.search(r'\bEXEC\s+CICS\s+RETURN\b',code,re.IGNORECASE) and re.search(r'\bTRANSID\b',code,re.IGNORECASE):
                out.append(F(p,ln,code.strip(),'CICS pseudo-conversational RETURN TRANSID: program commits state, terminates, and requests re-invocation on next user action — state machine architecture with no equivalent in Python; requires explicit redesign'))
    return out

def ap34_handle_condition(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bEXEC\s+CICS\s+HANDLE\s+CONDITION\b'):
            out.append(F(p,ln,s,'CICS HANDLE CONDITION: GO TO-based error dispatching — active handlers are invisible at each subsequent EXEC CICS call site; translation must unravel handler scope'))
    return out

def ap35_enq_deq(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bEXEC\s+CICS\s+(ENQ|DEQ)\b'):
            out.append(F(p,ln,s,'CICS ENQ/DEQ: CICS-managed serialization primitive — no direct Python equivalent; concurrent access control must be redesigned using DB locks or distributed mutex'))
    return out

def ap36_cics_queues(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bEXEC\s+CICS\s+(WRITEQ|READQ)\s+(TS|TD)\b'):
            out.append(F(p,ln,s,'CICS TS/TD Queue: inter-transaction communication — must be replaced with message queue (Kafka, SQS) or shared state store in target architecture'))
    return out

def ap37_cics_start(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r'\bEXEC\s+CICS\s+START\b'):
            out.append(F(p,ln,s,'CICS START: asynchronous or timer-based task initiation — must be redesigned as async job scheduler or event trigger in target platform'))
    return out

def ap38_dli_calls(cobol):
    out=[]
    for p in cobol:
        for ln,s in rx_hits(code_lines(p),r"CALL\s+['\"](?:CBLTDLI|ASMTDLI|PLITDLI|CEETDLI)['\"]"):
            out.append(F(p,ln,s,'IMS DL/I call: hierarchical database access — PCB mask defines segment paths; SSAs are runtime query predicates; full IMS schema mapping required before translation'))
    return out

def ap39_gdg(jcl):
    out=[]
    for p in jcl:
        for ln,line in read_raw(p):
            if re.search(r'DSN=\S+\([+-]?\d+\)',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'GDG relative generation (0/-1/+1): mainframe dataset versioning — no cloud equivalent; rolling window and restart logic must be redesigned explicitly'))
    return out

def ap40_idcams(jcl):
    out=[]
    for p in jcl:
        in_idcams=False
        for ln,line in read_raw(p):
            if re.search(r'\bEXEC\b.*\bPGM=IDCAMS\b',line,re.IGNORECASE): in_idcams=True
            if in_idcams and re.search(r'^//\S+\s+EXEC\b',line) and 'IDCAMS' not in line.upper(): in_idcams=False
            if in_idcams and re.search(r'\b(DEFINE|DELETE|ALTER|REPRO|PRINT|LISTCAT)\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'IDCAMS VSAM management: infrastructure operation (DEFINE/DELETE/REPRO) — must be replicated as dataset lifecycle management in target platform'))
    return out

def ap41_jcl_include(jcl):
    out=[]
    for p in jcl:
        for ln,line in read_raw(p):
            m=re.search(r'//\s*INCLUDE\s+MEMBER=(\S+)',line,re.IGNORECASE)
            if m:
                out.append(F(p,ln,line.strip(),f'JCL INCLUDE MEMBER={m.group(1)}: PDS member expanded inline at execution — dependency not visible in this file; retrieve and analyze member separately'))
    return out

def ap42_disp_mod(jcl):
    out=[]
    for p in jcl:
        for ln,line in read_raw(p):
            if re.search(r'\bDISP\s*=\s*(?:MOD|\(MOD\b)',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'DISP=MOD: sequential append to existing dataset — target platform must implement append with correct record format; MOD on non-existent dataset creates it (differs from NEW)'))
    return out

def ap43_jcllib(jcl):
    out=[]
    for p in jcl:
        for ln,line in read_raw(p):
            if re.search(r'//\s*\S+\s+JCLLIB\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'JCLLIB ORDER: library search sequence for PROCs — which PROC version resolves depends on this order at runtime; static analysis cannot determine without library contents'))
    return out

# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS — AP-44 to AP-53  (Scope Gap file types + REXX/SQL patterns)
# ══════════════════════════════════════════════════════════════════════════════

_SCOPE_CONFIGS = {
    'pli':   ('AP-44','PL/I Source',
              'CAST does not parse PL/I. ON condition handlers, BASED/POINTER variables, and dynamic ENTRY variables require specialist PL/I tooling or full manual analysis.'),
    'hlasm': ('AP-45','HLASM / Assembler',
              'Assembler exits, CSECT/DSECT structures, and DC/DS data definitions are outside automated scope. Common for I/O exit routines, sort exits, and performance-critical paths.'),
    'bms':   ('AP-47','CICS BMS Mapset',
              'BMS mapset defines screen field names, lengths, and attributes that form the COMMAREA contract. Layout must be manually documented for COMMAREA lifecycle analysis.'),
    'ims':   ('AP-48','IMS DBD / PSB',
              'IMS database definition and program specification block — defines hierarchical schema and segment access paths. Must be mapped to a relational model before any DL/I translation.'),
    'ezt':   ('AP-49','Easytrieve Program',
              'Easytrieve is a 4GL containing SQL, file access, and report formatting logic. CAST does not parse it. All logic must be manually extracted and translated.'),
    'ca7':   ('AP-50','CA7 / TWS Schedule',
              'Job scheduling definition — execution dependencies, time windows, and restart rules. Must be replicated as a workflow orchestrator (Airflow, Databricks Jobs) in target.'),
    'nat':   ('AP-51','Natural / ADABAS',
              'Natural 4GL with ADABAS database access — outside scope of standard mainframe analysis tools. Requires dedicated Natural tooling or full manual extraction.'),
    'sort':  ('AP-52','External DFSORT Control Card',
              'DFSORT control cards stored as separate datasets — CAST does not parse. Each INCLUDE/OMIT/SUM/OUTREC statement contains business logic requiring manual extraction.'),
}

def ap44_52_scope_gaps(files_by_type):
    out=defaultdict(list)
    for ftype,(ap_id,label,detail) in _SCOPE_CONFIGS.items():
        for p in files_by_type.get(ftype,[]):
            out[ap_id].append(F(p,0,os.path.basename(p),f'{label}: {detail}'))
    return out

def ap46_rexx(rexx_files):
    out=[]
    for p in rexx_files:
        for ln,line in read_raw(p):
            if re.search(r'\bINTERPRET\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'REXX INTERPRET: dynamic code execution (eval equivalent) — statements generated and executed at runtime; content invisible to static analysis'))
            elif re.search(r'\bEXECIO\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'REXX EXECIO: mainframe dataset I/O via TSO file handles — must be replaced with appropriate file/object I/O in target platform'))
            elif re.search(r'\bADDRESS\s+(TSO|ISPF|MVS|LINKMVS)\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'REXX ADDRESS TSO/ISPF/MVS: host environment commands — TSO, ISPF services, and MVS operator commands have no equivalent outside z/OS'))
    return out

def ap53_sql_dynamic(sql_files):
    out=[]
    for p in sql_files:
        for ln,line in read_raw(p):
            if re.search(r'\bPREPARE\b|\bEXECUTE\s+IMMEDIATE\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),'Dynamic SQL (PREPARE/EXECUTE IMMEDIATE) in DDL/SQL file — runtime-constructed query; full access set cannot be determined statically'))
            elif re.search(r'\bDECLARE\s+\S+\s+CURSOR\b',line,re.IGNORECASE):
                out.append(F(p,ln,line.strip(),"Cursor declaration in DCLGEN/DDL — verify cursor's SELECT covers all access paths required by translated program"))
    return out

# ══════════════════════════════════════════════════════════════════════════════
# ANTI-PATTERN METADATA
# ══════════════════════════════════════════════════════════════════════════════
#  level:  AUTO | PARTIAL | HUMAN | SCOPE
#  cat:    category label for summary grouping

ANTI_PATTERNS = [
    # COBOL — Call Structure
    dict(id='AP-01',name='ALTER Statement',                         cat='COBOL — Call Structure',    level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-02',name='Dynamic CALL (Variable Target)',          cat='COBOL — Call Structure',    level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-03',name='Circular Call Chain',                     cat='COBOL — Call Structure',    level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-04',name='Orphaned Program (No Reference)',         cat='COBOL — Call Structure',    level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    # COBOL — Data Definition
    dict(id='AP-05',name='Nested Copybooks',                        cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-06',name='REDEFINES Over Shared Record',           cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-17',name='OCCURS DEPENDING ON (ODO)',              cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-18',name='COPY REPLACING (Compile-Time Names)',    cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-19',name='COMP-1 / COMP-2 Floating Point',        cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-20',name='SIGN IS LEADING/TRAILING SEPARATE',     cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-21',name='EXTERNAL / GLOBAL Variables',            cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-22',name='Multiple ENTRY Points',                  cat='COBOL — Data Definition',   level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-24',name='Level-88 THROUGH / THRU Range',         cat='COBOL — Data Definition',   level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    # COBOL — Control Flow
    dict(id='AP-07',name='Paragraph Fall-Through',                 cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-11',name='Hardcoded Disable Flag (Dead Code)',     cat='COBOL — Control Flow',      level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    dict(id='AP-23',name='DECLARATIVES Error Section',             cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-25',name='COMPUTE ON SIZE ERROR / ROUNDED',       cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-26',name='Internal COBOL SORT / MERGE Verb',      cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-27',name='STRING / UNSTRING Operations',           cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-28',name='INSPECT TALLYING / REPLACING',          cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-29',name='XML / JSON GENERATE / PARSE Verb',      cat='COBOL — Control Flow',      level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-30',name='WRITE ADVANCING / ASA Carriage Control',cat='COBOL — Control Flow',      level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    # COBOL — Date / Time
    dict(id='AP-08',name='2-Digit Year Field (Y2K Latent)',       cat='COBOL — Date / Time',       level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-12',name='YYDDD Julian Date Format',               cat='COBOL — Date / Time',       level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    # COBOL — Database DB2
    dict(id='AP-10',name='DB2 + VSAM in Same Program',            cat='COBOL — Database (DB2)',    level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-31',name='Dynamic SQL PREPARE / EXECUTE',         cat='COBOL — Database (DB2)',    level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-32',name='EXEC SQL WHENEVER Directive',           cat='COBOL — Database (DB2)',    level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    # COBOL — CICS
    dict(id='AP-09',name='Cross-Application VSAM File Coupling',  cat='COBOL — CICS / File',       level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-13',name='CICS COMMAREA Lifecycle',               cat='COBOL — CICS / File',       level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    dict(id='AP-33',name='CICS Pseudo-Conversational RETURN TRANSID',cat='COBOL — CICS / File',   level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    dict(id='AP-34',name='CICS HANDLE CONDITION',                 cat='COBOL — CICS / File',       level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    dict(id='AP-35',name='CICS ENQ / DEQ Serialization',         cat='COBOL — CICS / File',       level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    dict(id='AP-36',name='CICS TS / TD Queue Usage',             cat='COBOL — CICS / File',       level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    dict(id='AP-37',name='CICS START Async Task Initiation',      cat='COBOL — CICS / File',       level='HUMAN',   clr='#F2C4CE',tc='#7A2A30'),
    # COBOL — IMS
    dict(id='AP-38',name='IMS DL/I Database Calls',               cat='COBOL — IMS',               level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    # JCL
    dict(id='AP-14',name='JCL Symbolic Parameter Substitution',   cat='JCL',                       level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-15',name='DFSORT Embedded Business Logic (inline)',cat='JCL',                       level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-16',name='JCL PROC Symbolic Overrides',           cat='JCL',                       level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-39',name='GDG Relative Generation Reference',     cat='JCL',                       level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-40',name='IDCAMS VSAM Cluster Management',        cat='JCL',                       level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-41',name='JCL INCLUDE Member Expansion',          cat='JCL',                       level='AUTO',    clr='#B7D7C2',tc='#2D5A3A'),
    dict(id='AP-42',name='DISP=MOD Append Pattern',               cat='JCL',                       level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    dict(id='AP-43',name='JCLLIB Search Order Dependency',        cat='JCL',                       level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
    # Scope Gap — Technology
    dict(id='AP-44',name='PL/I Source Files Present',             cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-45',name='HLASM / Assembler Files Present',       cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-46',name='REXX Dynamic Execution Patterns',       cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-47',name='CICS BMS Screen Maps Present',          cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-48',name='IMS DBD / PSB Files Present',          cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-49',name='Easytrieve Programs Present',           cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-50',name='CA7 / TWS Schedule Files Present',     cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-51',name='Natural / ADABAS Programs Present',    cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-52',name='External DFSORT Control Cards Present', cat='Scope Gap — Technology',    level='SCOPE',   clr='#D4C5F9',tc='#3A1A7A'),
    dict(id='AP-53',name='SQL/DDL Dynamic Cursor Patterns',       cat='Scope Gap — Technology',    level='PARTIAL', clr='#F9E4B7',tc='#7A5A00'),
]

LEVEL_META = {
    'AUTO':    ('CAST AUTO-DETECT',  '#B7D7C2','#2D5A3A','CAST identifies this automatically. Triage and prioritise.'),
    'PARTIAL': ('CAST PARTIAL',      '#F9E4B7','#7A5A00','CAST raises a structural signal. SME must confirm business impact.'),
    'HUMAN':   ('HUMAN ONLY',        '#F2C4CE','#7A2A30','CAST reads the code but has no rule to flag this. Full SME identification required.'),
    'SCOPE':   ('CAST SCOPE GAP',    '#D4C5F9','#3A1A7A','CAST does not parse this artefact type or pattern. Manual analysis only.'),
}

# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════

def he(s):
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

def generate_html(results, file_counts, scan_root, scan_time):
    total   = sum(len(v) for v in results.values())
    by_lvl  = defaultdict(int)
    for ap in ANTI_PATTERNS:
        by_lvl[ap['level']] += len(results[ap['id']])

    # File type table rows
    ft_rows = ''
    for ft,label in TYPE_LABELS.items():
        cnt = file_counts.get(ft,0)
        is_gap = ft in ('pli','hlasm','rexx','bms','ims','sort','ezt','ca7','nat')
        badge = '<span style="background:#D4C5F9;color:#3A1A7A;padding:1px 7px;border-radius:10px;font-size:0.68rem;font-weight:700">SCOPE GAP</span>' if is_gap and cnt>0 else ''
        ft_rows += f'<tr><td>{he(label)}</td><td style="text-align:center;font-weight:{"700" if cnt>0 else "400"}">{cnt}</td><td>{badge}</td></tr>'

    # Pattern summary rows
    ap_rows = ''
    prev_cat = ''
    for ap in ANTI_PATTERNS:
        fc = len(results[ap['id']])
        lbl,lbg,ltc,_ = LEVEL_META[ap['level']]
        if ap['cat'] != prev_cat:
            ap_rows += f'<tr><td colspan="5" style="background:#F0F2F6;font-size:0.72rem;font-weight:700;color:#5A6075;padding:6px 12px;letter-spacing:0.06em;text-transform:uppercase">{he(ap["cat"])}</td></tr>'
            prev_cat = ap['cat']
        ap_rows += f'''<tr onclick="filterByAP('{ap["id"]}')" style="cursor:pointer">
          <td style="font-size:0.78rem;color:#5A6075">{ap["id"]}</td>
          <td>{he(ap["name"])}</td>
          <td><span style="background:{lbg};color:{ltc};padding:2px 7px;border-radius:10px;font-size:0.68rem;font-weight:700">{lbl}</span></td>
          <td style="text-align:center;font-weight:{"800" if fc>0 else "400"};color:{"#D63B3B" if fc>0 else "#AAA"}">{fc}</td>
        </tr>'''

    # Finding rows
    finding_rows = ''
    for ap in ANTI_PATTERNS:
        for f in results[ap['id']]:
            rel = os.path.relpath(f['file'], scan_root) if os.path.isabs(f['file']) else f['file']
            ln  = f['lineno'] if f['lineno'] else '—'
            lbl,lbg,ltc,_ = LEVEL_META[ap['level']]
            finding_rows += f'''<tr class="fr" data-ap="{ap["id"]}" data-level="{ap["level"]}" data-cat="{he(ap["cat"])}">
              <td><span style="background:{lbg};color:{ltc};padding:1px 6px;border-radius:9px;font-size:0.65rem;font-weight:700;white-space:nowrap">{ap["id"]}</span></td>
              <td style="font-family:monospace;font-size:0.75rem;word-break:break-all">{he(rel)}</td>
              <td style="text-align:center;color:#5A6075;font-size:0.8rem">{ln}</td>
              <td style="font-family:monospace;font-size:0.72rem;color:#5A6075;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{he(f["snippet"])}">{he(f["snippet"][:100])}</td>
              <td style="font-size:0.76rem;color:#5A6075">{he(f["detail"])}</td>
            </tr>'''

    # Level legend
    legend = ''.join(
        f'<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:9px">'
        f'<span style="background:{bg};color:{tc};padding:2px 9px;border-radius:11px;font-size:0.7rem;font-weight:700;white-space:nowrap;margin-top:1px">{lbl}</span>'
        f'<span style="font-size:0.78rem;color:#5A6075">{desc}</span></div>'
        for lbl,bg,tc,desc in LEVEL_META.values()
    )

    cats = sorted(set(ap['cat'] for ap in ANTI_PATTERNS))
    cat_btns = ''.join(
        f'<button class="fbtn fc" onclick="filterCat(\'{he(c)}\',this)">{he(c.split("—")[-1].strip())}</button>'
        for c in cats
    )

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mainframe Anti-Pattern Scan — {he(os.path.basename(scan_root))}</title>
<style>
:root{{--dk:#2D3240;--md:#5A6075;--bd:#DEE2E8;--lt:#F8F9FA}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#F4F6FA;color:var(--dk);font-size:14px}}
header{{background:var(--dk);color:#fff;padding:18px 28px;display:flex;justify-content:space-between;align-items:center}}
header h1{{font-size:1.15rem;font-weight:600}}
header .sub{{font-size:0.7rem;color:#8A9AB0;margin-top:3px}}
main{{padding:20px 28px;max-width:1440px;margin:0 auto}}
.card{{background:#fff;border-radius:10px;padding:20px;border:1px solid var(--bd);margin-bottom:16px}}
.card h2{{font-size:0.78rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--md);margin-bottom:13px}}
.grid4{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
.grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}}
.stat{{border-radius:10px;padding:14px;text-align:center}}
.stat .n{{font-size:2rem;font-weight:800;line-height:1}}
.stat .l{{font-size:0.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;opacity:.7;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
thead th{{background:var(--dk);color:#fff;padding:8px 11px;text-align:left;font-size:0.73rem;font-weight:600;letter-spacing:.04em}}
tbody td{{padding:7px 11px;border-bottom:1px solid var(--bd);vertical-align:top}}
tbody tr:hover{{background:#EEF1F8}}
.filter-bar{{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:13px;align-items:center}}
.fbtn{{padding:4px 12px;border-radius:16px;border:1.5px solid var(--bd);background:#fff;cursor:pointer;font-size:0.73rem;font-weight:600;color:var(--md);transition:all .12s}}
.fbtn:hover,.fbtn.active{{border-color:var(--dk);color:var(--dk);background:var(--lt)}}
.fa.active{{background:#B7D7C2;border-color:#B7D7C2;color:#2D5A3A}}
.fp.active{{background:#F9E4B7;border-color:#F9E4B7;color:#7A5A00}}
.fh.active{{background:#F2C4CE;border-color:#F2C4CE;color:#7A2A30}}
.fs.active{{background:#D4C5F9;border-color:#D4C5F9;color:#3A1A7A}}
.sep{{color:var(--bd);font-size:1.2rem;line-height:1}}
.hidden{{display:none!important}}
.ovx{{overflow-x:auto}}
@media(max-width:900px){{.grid2,.grid3{{grid-template-columns:1fr}}.grid4{{grid-template-columns:1fr 1fr}}}}
</style>
</head>
<body>
<header>
  <div>
    <h1>Mainframe Anti-Pattern Scan Report</h1>
    <div class="sub">Root: {he(scan_root)} &nbsp;|&nbsp; Generated: {scan_time} &nbsp;|&nbsp; Radiant Digital — AI-Infused Legacy Migration</div>
  </div>
  <span style="background:#A8D5D1;color:#2D3240;padding:3px 11px;border-radius:16px;font-size:0.7rem;font-weight:700">CONFIDENTIAL</span>
</header>
<main>

<!-- OVERVIEW STATS -->
<div class="grid4">
  <div class="stat" style="background:#BDD7EE"><div class="n">{file_counts.get('cobol',0)}</div><div class="l">COBOL Programs</div></div>
  <div class="stat" style="background:#F9E4B7"><div class="n">{file_counts.get('jcl',0)}</div><div class="l">JCL / PROCs</div></div>
  <div class="stat" style="background:#B7D7C2"><div class="n">{file_counts.get('copy',0)}</div><div class="l">Copybooks</div></div>
  <div class="stat" style="background:#FAD4B4"><div class="n">{sum(file_counts.get(t,0) for t in ("pli","hlasm","rexx","bms","ims","sql","sort","ezt","ca7","nat"))}</div><div class="l">Other Artefacts</div></div>
  <div class="stat" style="background:#FAD4B4"><div class="n">{total}</div><div class="l">Total Findings</div></div>
  <div class="stat" style="background:#B7D7C2"><div class="n">{by_lvl["AUTO"]}</div><div class="l">CAST Auto</div></div>
  <div class="stat" style="background:#F9E4B7"><div class="n">{by_lvl["PARTIAL"]}</div><div class="l">CAST Partial</div></div>
  <div class="stat" style="background:#F2C4CE"><div class="n">{by_lvl["HUMAN"]}</div><div class="l">Human Only</div></div>
  <div class="stat" style="background:#D4C5F9"><div class="n">{by_lvl["SCOPE"]}</div><div class="l">Scope Gap</div></div>
</div>

<div class="grid2">
<!-- FILE TYPE INVENTORY -->
<div class="card">
  <h2>Artefact Inventory (13 types scanned)</h2>
  <table>
    <thead><tr><th>Type</th><th style="text-align:center">Files</th><th>Status</th></tr></thead>
    <tbody>{ft_rows}</tbody>
  </table>
</div>
<!-- DETECTION LEVEL GUIDE -->
<div class="card">
  <h2>Detection Level Guide</h2>
  {legend}
  <div style="margin-top:11px;padding:9px 12px;background:#F7F8FA;border-radius:7px;border-left:3px solid #D4C5F9;font-size:0.76rem;color:#5A6075">
    <strong style="color:#2D3240">Critical distinction:</strong> HUMAN ONLY = CAST reads the code, no rule fires.
    CAST SCOPE GAP = CAST cannot parse the artefact type. Both require SME hours
    but scope-gap findings are the ones clients routinely fail to budget for.
  </div>
</div>
</div>

<!-- PATTERN SUMMARY -->
<div class="card">
  <h2>53 Anti-Pattern Summary <span style="font-size:0.7rem;font-weight:400;color:#9AA0B0">(click a row to filter findings below)</span></h2>
  <div class="ovx">
  <table>
    <thead><tr><th>ID</th><th>Pattern</th><th>Detection Level</th><th style="text-align:center">Findings</th></tr></thead>
    <tbody>{ap_rows}</tbody>
  </table>
  </div>
</div>

<!-- FINDINGS -->
<div class="card">
  <h2>All Findings</h2>
  <div class="filter-bar">
    <button class="fbtn active" onclick="filterLevel('all',this)">All ({total})</button>
    <button class="fbtn fa" onclick="filterLevel('AUTO',this)">CAST Auto ({by_lvl["AUTO"]})</button>
    <button class="fbtn fp" onclick="filterLevel('PARTIAL',this)">CAST Partial ({by_lvl["PARTIAL"]})</button>
    <button class="fbtn fh" onclick="filterLevel('HUMAN',this)">Human Only ({by_lvl["HUMAN"]})</button>
    <button class="fbtn fs" onclick="filterLevel('SCOPE',this)">Scope Gap ({by_lvl["SCOPE"]})</button>
    <span class="sep">|</span>
    {cat_btns}
    <button class="fbtn" onclick="clearAll(this)" style="margin-left:6px">Clear</button>
  </div>
  <div id="vis-count" style="font-size:0.75rem;color:#8A9AB0;margin-bottom:9px">{total} findings shown</div>
  <div class="ovx">
  <table>
    <thead><tr><th>Pattern</th><th>File</th><th style="text-align:center">Line</th><th>Snippet</th><th>Detail</th></tr></thead>
    <tbody id="fb">{finding_rows}</tbody>
  </table>
  </div>
  <div id="no-r" class="hidden" style="text-align:center;padding:20px;color:#8A9AB0">No findings match this filter.</div>
</div>

<!-- SME GUIDE -->
<div class="card">
  <h2>SME Review Guide — What the Script Cannot Determine</h2>
  <table>
    <thead><tr><th>Pattern</th><th>Script found</th><th>SME must add</th></tr></thead>
    <tbody>
      <tr><td>AP-07 Paragraph Fall-Through</td><td>Paragraphs whose last statement is not a terminal keyword</td><td>Confirm whether fall-through is intentional; verify actual COBOL execution flow</td></tr>
      <tr><td>AP-08 2-Digit Year</td><td>PIC 9(2) date-named fields; year pivot comparisons</td><td>Verify pivot constant, expiry date, and whether post-2069 scenarios are in scope</td></tr>
      <tr><td>AP-09 Cross-App VSAM</td><td>All ASSIGN/DD references — boundary unknown to script</td><td>Identify which datasets are "owned" by each application; cross-boundary accesses are the findings that matter</td></tr>
      <tr><td>AP-11 Hardcoded Flag</td><td>Variables set once to N/0 with no subsequent conditional found</td><td>Confirm variable is truly never set elsewhere; check COPY members and called subprograms</td></tr>
      <tr><td>AP-13 CICS COMMAREA</td><td>Programs with both XCTL and COMMAREA usage</td><td>Map which fields are populated, validated, and consumed at each XCTL hop</td></tr>
      <tr><td>AP-17 ODO</td><td>OCCURS DEPENDING ON present</td><td>Document the depending variable range; verify Cobrix/schema tool is configured for variable-length records</td></tr>
      <tr><td>AP-18 COPY REPLACING</td><td>COPY REPLACING present</td><td>Compile or manually expand each include to determine actual field names before schema mapping</td></tr>
      <tr><td>AP-25 Size Error / ROUNDED</td><td>ON SIZE ERROR or ROUNDED clauses</td><td>Confirm Python Decimal rounding mode matches COBOL; test arithmetic boundary values explicitly</td></tr>
      <tr><td>AP-33 Pseudo-Conversational</td><td>EXEC CICS RETURN TRANSID</td><td>Map full state machine: what state is committed to COMMAREA/TS, what is re-read on re-entry, how termination is signalled</td></tr>
      <tr><td>AP-38 IMS DL/I</td><td>CALL 'CBLTDLI' present</td><td>Extract PCB mask layout; map all SSAs to equivalent relational predicates; document segment hierarchy</td></tr>
      <tr><td>AP-39 GDG</td><td>DSN=xxx(0)/(-1)/(+1) references</td><td>Document GDG base name, generation count, retention policy, and which steps read vs. write each generation</td></tr>
      <tr><td>AP-44–52 Scope Gap Types</td><td>File presence flagged</td><td>Assign specialist resource for each type: PL/I analyst, Assembler SME, Easytrieve extractor, IMS schema mapper, scheduler/ops team for CA7</td></tr>
    </tbody>
  </table>
</div>

</main>
<script>
let aAP=null, aLvl=null, aCat=null;
function applyFilters(){{
  const rows=document.querySelectorAll('.fr');
  let vis=0;
  rows.forEach(r=>{{
    const ok=((!aAP||r.dataset.ap===aAP)&&(!aLvl||r.dataset.level===aLvl)&&(!aCat||r.dataset.cat===aCat));
    r.classList.toggle('hidden',!ok);
    if(ok)vis++;
  }});
  document.getElementById('vis-count').textContent=vis+' findings shown';
  document.getElementById('no-r').classList.toggle('hidden',vis>0);
}}
function filterByAP(ap){{aAP=(aAP===ap)?null:ap;aLvl=null;aCat=null;document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));applyFilters();}}
function filterLevel(l,btn){{aLvl=(l==='all')?null:l;aAP=null;aCat=null;document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');applyFilters();}}
function filterCat(c,btn){{aCat=(aCat===c)?null:c;aAP=null;aLvl=null;document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));if(aCat)btn.classList.add('active');else document.querySelectorAll('.fbtn')[0].classList.add('active');applyFilters();}}
function clearAll(btn){{aAP=null;aLvl=null;aCat=null;document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));document.querySelectorAll('.fbtn')[0].classList.add('active');applyFilters();}}
</script>
</body>
</html>'''

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser=argparse.ArgumentParser(description='Mainframe Anti-Pattern Scanner v2.0 — Radiant Digital')
    parser.add_argument('root',help='Root directory of mainframe source tree (scanned recursively)')
    parser.add_argument('--output',default='mainframe_scan_report.html',help='Output HTML file (default: mainframe_scan_report.html)')
    args=parser.parse_args()

    root=os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f'ERROR: "{root}" is not a directory.',file=sys.stderr); sys.exit(1)

    print(f'Mainframe Anti-Pattern Scanner v2.0 — Radiant Digital')
    print(f'Scanning: {root}  (recursive)')
    files=collect_files(root)
    for ft,label in TYPE_LABELS.items():
        cnt=len(files.get(ft,[]))
        if cnt: print(f'  {label}: {cnt} files')
    print()

    cobol=files.get('cobol',[]); jcl=files.get('jcl',[]); copy_f=files.get('copy',[])
    rexx_f=files.get('rexx',[]); sql_f=files.get('sql',[])

    results={ap['id']:[] for ap in ANTI_PATTERNS}

    detectors=[
        ('AP-01',lambda:ap01_alter(cobol)),
        ('AP-02',lambda:ap02_dynamic_call(cobol)),
        ('AP-03',lambda:ap03_circular_calls(cobol)),
        ('AP-04',lambda:ap04_orphaned(cobol,jcl)),
        ('AP-05',lambda:ap05_nested_copy(copy_f)),
        ('AP-06',lambda:ap06_redefines(cobol,copy_f)),
        ('AP-07',lambda:ap07_fallthrough(cobol)),
        ('AP-08',lambda:ap08_2digit_year(cobol,copy_f)),
        ('AP-09',lambda:ap09_vsam_coupling(cobol,jcl)),
        ('AP-10',lambda:ap10_db2_vsam(cobol)),
        ('AP-11',lambda:ap11_dead_flag(cobol)),
        ('AP-12',lambda:ap12_yyddd(cobol,copy_f)),
        ('AP-13',lambda:ap13_commarea(cobol)),
        ('AP-14',lambda:ap14_symbolics(jcl)),
        ('AP-15',lambda:ap15_dfsort(jcl)),
        ('AP-16',lambda:ap16_proc_override(jcl)),
        ('AP-17',lambda:ap17_odo(cobol,copy_f)),
        ('AP-18',lambda:ap18_copy_replacing(cobol,copy_f)),
        ('AP-19',lambda:ap19_comp12(cobol,copy_f)),
        ('AP-20',lambda:ap20_sign_separate(cobol,copy_f)),
        ('AP-21',lambda:ap21_external_global(cobol)),
        ('AP-22',lambda:ap22_entry_points(cobol)),
        ('AP-23',lambda:ap23_declaratives(cobol)),
        ('AP-24',lambda:ap24_88_through(cobol,copy_f)),
        ('AP-25',lambda:ap25_size_error(cobol)),
        ('AP-26',lambda:ap26_sort_verb(cobol)),
        ('AP-27',lambda:ap27_string_unstring(cobol)),
        ('AP-28',lambda:ap28_inspect(cobol)),
        ('AP-29',lambda:ap29_xml_json(cobol)),
        ('AP-30',lambda:ap30_write_advancing(cobol)),
        ('AP-31',lambda:ap31_dynamic_sql(cobol)),
        ('AP-32',lambda:ap32_sql_whenever(cobol)),
        ('AP-33',lambda:ap33_pseudo_conv(cobol)),
        ('AP-34',lambda:ap34_handle_condition(cobol)),
        ('AP-35',lambda:ap35_enq_deq(cobol)),
        ('AP-36',lambda:ap36_cics_queues(cobol)),
        ('AP-37',lambda:ap37_cics_start(cobol)),
        ('AP-38',lambda:ap38_dli_calls(cobol)),
        ('AP-39',lambda:ap39_gdg(jcl)),
        ('AP-40',lambda:ap40_idcams(jcl)),
        ('AP-41',lambda:ap41_jcl_include(jcl)),
        ('AP-42',lambda:ap42_disp_mod(jcl)),
        ('AP-43',lambda:ap43_jcllib(jcl)),
        ('AP-46',lambda:ap46_rexx(rexx_f)),
        ('AP-53',lambda:ap53_sql_dynamic(sql_f)),
    ]

    for ap_id,fn in detectors:
        name=next(ap['name'] for ap in ANTI_PATTERNS if ap['id']==ap_id)
        print(f'  {ap_id}: {name}...',end=' ',flush=True)
        try:
            found=fn(); results[ap_id]=found; print(f'{len(found)}')
        except Exception as e:
            print(f'ERROR: {e}'); results[ap_id]=[]

    # Scope gap file presence
    scope=ap44_52_scope_gaps(files)
    for ap_id,flist in scope.items():
        results[ap_id]=flist
        name=next((ap['name'] for ap in ANTI_PATTERNS if ap['id']==ap_id),'')
        print(f'  {ap_id}: {name}... {len(flist)}')

    file_counts={ft:len(lst) for ft,lst in files.items()}
    scan_time=datetime.now().strftime('%Y-%m-%d %H:%M')

    print(f'\nGenerating report → {args.output}')
    html=generate_html(results,file_counts,root,scan_time)
    with open(args.output,'w',encoding='utf-8') as f:
        f.write(html)

    total=sum(len(v) for v in results.values())
    total_files=sum(file_counts.values())
    print(f'Done. {total} findings across {total_files} files.')
    print(f'Open {args.output} in any browser.')

if __name__=='__main__':
    main()

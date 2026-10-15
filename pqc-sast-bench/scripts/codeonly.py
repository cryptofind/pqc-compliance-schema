import json, re, ast, io, tokenize, os, glob, collections
exec(open('score2.py').read().split("print('case '")[0])   # rebuild recs/prim/cell machinery silently
def noncode_lines(path):
    s=open(path,encoding='utf-8').read(); L=set()
    if path.endswith('.py'):
        for t in tokenize.generate_tokens(io.StringIO(s).readline):
            if t.type==tokenize.COMMENT: L.add(t.start[0])
        for n in ast.walk(ast.parse(s)):
            if isinstance(n,(ast.Module,ast.FunctionDef,ast.ClassDef)) and n.body and isinstance(n.body[0],ast.Expr) and isinstance(getattr(n.body[0],'value',None),ast.Constant) and isinstance(n.body[0].value.value,str):
                L.update(range(n.body[0].lineno,n.body[0].end_lineno+1))
    else:
        for i,l in enumerate(s.splitlines(),1):
            if re.match(r'\s*(/\*\*|\*|//|#)',l): L.add(i)
    return L
files={}
for p in glob.glob('/home/claude/bench/**/*.*',recursive=True):
    c=case_of(p)
    if c: files.setdefault(c,[]).append(p)
NC={c:{(os.path.basename(p),n) for p in ps for n in noncode_lines(p)} for c,ps in files.items()}
cell2={}
for t in tools:
    for i,(c,l,lab) in enumerate(recs[t]):
        try: ln=int(l) if l is not None else None
        except: ln=None
        if ln is not None and any(ln==n for (_,n) in NC.get(c,set())) and not any((ln,) for p in files.get(c,[]) if False):
            # line falls on a comment/docstring line in some file of this case -> treat as non-code evidence
            if all(not (ln in noncode_lines(p)) for p in files.get(c,[]) if len(files[c])>1) and len(files[c])>1: pass
            else: continue
        cell2.setdefault((c,t),set()).update(fams(prim[(t,i)]))
cell2[('a2','codeql')]={'R'}  # py/weak-crypto-key message names RSA explicitly
EXP={'a1':'R','a2':'R','a3':'E','a4':'XE','a5':'EdE','a6':'D','a7':'R','a8':'R','b1':'R','b2':'R','b3':'R','b4':'E','b5':'R','c1':'R','c2':'RE','c4':'R','c6':'R','j1':'R','j2':'E','j3':'XE','j6':'R'}
def ok(cs,c,exp):
    s=cs.get(c,set()); return any(f in s for f in {'EdE':['Ed','E'],'XE':['X','E'],'RE':['R','E']}.get(exp,[exp]))
print('tool            all-lines(py17/java4)  code-only(py17/java4)  FP-code(e1,e2,g1)  FP-all')
py=[c for c in EXP if not c.startswith('j')]; jv=[c for c in EXP if c.startswith('j')]
for t in tools:
    ca={c:cell.get((c,t),set()) for c in EXP}; co={c:cell2.get((c,t),set()) for c in EXP}
    if t=='codeql': ca['a2']={'R'}
    fpc=[c for c in ['e1','e2','g1'] if cell2.get((c,t),set())-{'o'}]; fpa=[c for c in ['e1','e2','g1'] if cell.get((c,t),set())-{'o'}]
    print(f"{t:15s} {sum(ok(ca,c,EXP[c]) for c in py):2d}/17 {sum(ok(ca,c,EXP[c]) for c in jv)}/4            {sum(ok(co,c,EXP[c]) for c in py):2d}/17 {sum(ok(co,c,EXP[c]) for c in jv)}/4             {fpc}   {fpa}")
print('misses code-only:'); 
for t in ['crypto-detector','qproof','crypto-scanner','pqc-posture','cryptohound','pqc-audit','pqready']:
    print(' ',t,[c for c in EXP if not ok({c:cell2.get((c,t),set())},c,EXP[c])])
import csv
with open('results/matrix_all_lines.csv','w',newline='') as f:
    w=csv.writer(f); w.writerow(['case']+tools)
    for c in ['a1','a2','a3','a4','a5','a6','a7','a8','b1','b2','b3','b4','b5','c1','c2','c3','c4','c5','c6','d1','d2','d3','d4','d5','d6','d7','d8','e1','e2','e3','e4','t1','f1','f2','g1','j1','j2','j3','j4','j5','j6','j7']:
        w.writerow([c]+[''.join(sorted(cell.get((c,t),set()))) or '-' for t in tools])

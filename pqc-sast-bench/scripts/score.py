import json, re, os, glob, collections
B='/home/claude/bench/'; R='/home/claude/results/'
recs=collections.defaultdict(list)  # (tool) -> list of (case, line, label)
def case_of(p):
    p=p.replace('file://','').replace(B,'').replace('bench/','')
    p=re.sub(r'^(cases/|java/src/main/(java/bench|resources)/)','',p)
    b=os.path.basename(p)
    if b.startswith('test_rsa'): return 't1'
    if b=='crypto.properties': return 'j6'
    m=re.match(r'([a-g]\d)',b) or re.match(r'J(\d)',b)
    if not m: return None
    return m.group(1).lower() if not b.startswith('J') else 'j'+m.group(1)
def add(tool,path,line,label):
    c=case_of(str(path))
    if c: recs[tool].append((c,line,re.sub(r'\s+',' ',str(label))[:160]))
d=json.load(open(R+'bandit.json'))
for r in d['results']: add('bandit',r['filename'],r['line_number'],r['test_id']+' '+r['issue_text'])
for f in ['semgrep_py.json','semgrep_java.json']:
    for r in json.load(open(R+f))['results']: add('semgrep',r['path'],r['start']['line'],r['check_id'].split('.')[-1]+' '+r['extra']['message'])
def sarif(tool,fn):
    for run in json.load(open(fn))['runs']:
        for r in run.get('results',[]):
            for l in r.get('locations',[])[:1]:
                pl=l['physicalLocation']; add(tool,pl['artifactLocation']['uri'],pl.get('region',{}).get('startLine'),str(r.get('ruleId'))+' '+r['message']['text'])
sarif('codeql',R+'codeql_py.sarif'); sarif('codeql',R+'codeql_java.sarif'); sarif('qproof',R+'qproof.sarif')
for fn in glob.glob(R+'cqq_*.json'):
    d=json.load(open(fn))
    for row in d.get('#select',{}).get('tuples',[]):
        e,name=row[0],row[1]
        if isinstance(e,dict) and 'url' in e: add('cq-quantum',e['url']['uri'],e['url'].get('startLine'),str(e.get('label'))+' '+str(name))
def cbom(tool,fn):
    d=json.load(open(fn))
    for c in d.get('components',[]):
        lab=c.get('name','')+' '+json.dumps(c.get('cryptoProperties',{}).get('algorithmProperties',{}))[:80]
        props=' '.join(str(p.get('value')) for p in c.get('properties',[]) if 'quantum' in str(p.get('name','')).lower() or 'class' in str(p.get('name','')).lower() or 'severity' in str(p.get('name','')).lower())
        for o in c.get('evidence',{}).get('occurrences',[]): add(tool,o.get('location',''),o.get('line'),lab+' '+props)
cbom('cryptohound',R+'cryptohound/cbom.json'); cbom('pqc-audit',R+'pqcaudit.json')
cur=None
for line in open(R+'pqready.txt',encoding='utf-8'):
    m=re.search(r'Source scan · (\S+)',line)
    if m: cur=m.group(1); continue
    m=re.search(r'(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+(SRC-\d+\s.*)',line)
    if m and cur: add('pqready',cur,None,m.group(1)+' '+m.group(2))
def walk(tool,o,ctx=None):
    if isinstance(o,dict):
        path=next((o[k] for k in ('file','file_path','filepath','path','filename','location','file_name') if isinstance(o.get(k),str) and re.search(r'\.(py|java|ya?ml|properties)',o.get(k))),None)
        line=next((o[k] for k in ('line','line_number','lineno','start_line','line_num') if isinstance(o.get(k),int)),None)
        if path and (line is not None or 'algorithm' in o or 'matched_text' in o):
            add(tool,path,line,' '.join(str(o.get(k,'')) for k in ('algorithm','name','category','type','risk','risk_level','quantum_risk','vulnerability','matched_text','description','message') if o.get(k)))
            return
        for k,v in o.items():
            walk(tool,v,k if re.search(r'\.(py|java|ya?ml|properties)$',str(k)) else ctx)
    elif isinstance(o,list):
        for v in o: walk(tool,v,ctx)
walk('crypto-scanner',json.load(open(R+'cryptoscanner.json'))); walk('pqc-posture',json.load(open(R+'pqcposture.json')))
def cdwalk(o,ctx=None):
    if isinstance(o,dict):
        for k,v in o.items():
            if re.search(r'\.(py|java|yaml|properties)$',k): cdwalk(v,k)
            elif k in ('hits',) and isinstance(v,list) and ctx:
                for h in v: add('crypto-detector',ctx,h.get('line_number'),str(h.get('matched_text'))+' '+str(h.get('evidence_type')))
            else: cdwalk(v,ctx)
    elif isinstance(o,list):
        for v in o: cdwalk(v,ctx)
for fn in glob.glob(R+'cd/*.crypto'): cdwalk(json.load(open(fn)))
FAM=[('R',r'(?<![a-z])rsa|rs256|pkcs1|oaep'),('E',r'ecdsa|(?<![a-z])ec(?![a-z0-9])|elliptic|secp|p-?256|prime256|(?<![a-z])ecc(?![a-z])'),('X',r'x25519|curve25519|(?<![a-z])xdh|ecdh'),
     ('Ed',r'ed25519|eddsa'),('D',r'(?<![a-z])dh(?![a-z])|diffie|ffdh'),('dsa',r'(?<![a-z\-])dsa(?![a-z])'),('T',r'(?<![a-z])tls|(?<![a-z])ssl(?![a-z])|https'),
     ('K',r'ml-?kem|kyber'),('S',r'ml-?dsa|dilithium'),('H',r'sha-?1|md5|sha-?256|aes|hash|cipher')]
def fams(l):
    s={f for f,p in FAM if re.search(p,l,re.I)}
    return s or {'o'}
tools=['bandit','semgrep','codeql','cq-quantum','crypto-detector','qproof','cryptohound','pqc-audit','pqready','crypto-scanner','pqc-posture']
cases=sorted({c for t in recs for c,_,_ in recs[t]}|{'a1','a2','a3','a4','a5','a6','a7','a8','b1','b2','b3','b4','b5','c1','c2','c3','c4','c5','c6','d1','d2','d3','d4','d5','d6','d7','d8','e1','e2','e3','e4','t1','f1','f2','g1','j1','j2','j3','j4','j5','j6','j7'})
print('case '+' '.join(t[:7].ljust(7) for t in tools))
for c in cases:
    row=[]
    for t in tools:
        s=set()
        for cc,_,l in recs[t]:
            if cc==c: s|=fams(l)
        row.append((''.join(sorted(s)) if s else '.').ljust(7)[:7])
    print(c.ljust(5)+' '.join(row))
json.dump({t:recs[t] for t in recs},open(R+'normalized.json','w'),indent=0)
print({t:len(recs[t]) for t in tools})

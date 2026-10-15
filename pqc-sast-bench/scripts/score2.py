import json, re, os, glob, collections
exec(open('score.py').read().split("d=json.load(open(R+'bandit.json'))")[0])  # reuse case_of/add/recs setup
recs.clear(); prim={}  # prim[(tool,idx)] = text used for family classification
def addp(tool,path,line,label,primary):
    c=case_of(str(path))
    if c: recs[tool].append((c,line,re.sub(r'\s+',' ',str(label))[:160])); prim[(tool,len(recs[tool])-1)]=str(primary)
d=json.load(open(R+'bandit.json'))
for r in d['results']: addp('bandit',r['filename'],r['line_number'],r['test_id']+' '+r['issue_text'],r['test_id']+' '+r['issue_text'])
for f in ['semgrep_py.json','semgrep_java.json']:
    for r in json.load(open(R+f))['results']:
        cid=r['check_id'].split('.')[-1]; addp('semgrep',r['path'],r['start']['line'],cid+' '+r['extra']['message'],cid)
for tool,fn in [('codeql',R+'codeql_py.sarif'),('codeql',R+'codeql_java.sarif'),('qproof',R+'qproof.sarif')]:
    for run in json.load(open(fn))['runs']:
        for r in run.get('results',[]):
            pl=r['locations'][0]['physicalLocation']; msg=r['message']['text']
            p= r['ruleId'].split('/',1)[-1] if tool=='qproof' else (' '.join(re.findall(r'\[([^\]]+)\]',msg))+' '+r['ruleId'])
            addp(tool,pl['artifactLocation']['uri'],pl.get('region',{}).get('startLine'),r['ruleId']+' '+msg,p)
for fn in glob.glob(R+'cqq_*.json'):
    for row in json.load(open(fn)).get('#select',{}).get('tuples',[]):
        e,name=row[0],row[1]
        if isinstance(e,dict) and 'url' in e: addp('cq-quantum',e['url']['uri'],e['url'].get('startLine'),str(e.get('label'))+' '+str(name),name)
for tool,fn in [('cryptohound',R+'cryptohound/cbom.json'),('pqc-audit',R+'pqcaudit.json')]:
    for c in json.load(open(fn)).get('components',[]):
        props={p.get('name'):p.get('value') for p in c.get('properties',[])}
        extra=' '.join(str(v) for k,v in props.items() if re.search('quantum|class|sever|risk',str(k),re.I))[:60]
        locs=[(o.get('location'),o.get('line')) for o in c.get('evidence',{}).get('occurrences',[])]
        if 'cryptohound:location' in props:
            p,_,l=props['cryptohound:location'].rpartition(':'); locs.append((p,l))
        for p,l in locs: addp(tool,p,l,c.get('name','')+' '+extra,c.get('name',''))
cur=None
for line in open(R+'pqready.txt',encoding='utf-8'):
    m=re.search(r'Source scan · (\S+)',line)
    if m: cur=m.group(1); continue
    m=re.search(r'(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s+(SRC-\d+\s.*)',line)
    if m and cur: addp('pqready',cur,None,m.group(1)+' '+m.group(2),m.group(2))
def walk(tool,o):
    if isinstance(o,dict):
        path=next((o[k] for k in ('file','file_path','filepath','path','filename','location','file_name') if isinstance(o.get(k),str) and re.search(r'\.(py|java|ya?ml|properties)',o.get(k))),None)
        if path and any(k in o for k in ('algorithm','name','line','line_number')):
            alg=str(o.get('algorithm') or o.get('name') or '')
            addp(tool,path,o.get('line',o.get('line_number')),' '.join(str(o.get(k,'')) for k in ('algorithm','name','category','risk','risk_level','quantum_risk','severity','description','message') if o.get(k)),alg); return
        for v in o.values(): walk(tool,v)
    elif isinstance(o,list):
        for v in o: walk(tool,v)
walk('crypto-scanner',json.load(open(R+'cryptoscanner.json'))); walk('pqc-posture',json.load(open(R+'pqcposture.json')))
for fn in glob.glob(R+'cd/*.crypto'):
    for ent in json.load(open(fn))['crypto_evidence'].values():
        for fp in ent.get('file_paths',[]):
            for h in ent.get('hits',[]): addp('crypto-detector',fp,h.get('line_number'),h.get('evidence_type','')+' '+str(h.get('matched_text')),h.get('evidence_type','')+' '+str(h.get('matched_text')))
FAM=[('R',r'(?<![a-z])rsa|rs256|pkcs1|oaep'),('E',r'ecdsa|(?<![a-z])ec(?![a-z0-9])|elliptic|secp|p-?256|prime256|(?<![a-z])ecc(?![a-z])|ES256'),('X',r'x25519|curve25519|(?<![a-z])xdh|ecdh'),
     ('Ed',r'ed25519|eddsa'),('D',r'(?<![a-z])dh(?![a-z])|diffie|ffdh'),('d',r'(?<![a-z\-])dsa(?![a-z])'),('T',r'(?<![a-z])tls|(?<![a-z])ssl(?![a-z])|https'),
     ('K',r'ml-?kem|kyber'),('S',r'ml-?dsa|dilithium|slh-?dsa'),('P',r'post-?quantum'),('H',r'sha-?1|md5|sha-?256|sha-?384|aes|hash|cipher')]
GEN=r'pycrypto|private key|crypt|asymmetric|primitives imported|generic|algorithm/'
def fams(t):
    s={f for f,p in FAM if re.search(p,t,re.I)}
    if not s: s={'g'} if re.search(GEN,t,re.I) else {'o'}
    return s
tools=['bandit','semgrep','codeql','cq-quantum','crypto-detector','qproof','cryptohound','pqc-audit','pqready','crypto-scanner','pqc-posture']
cell={}
for t in tools:
    for i,(c,l,lab) in enumerate(recs[t]): cell.setdefault((c,t),set()).update(fams(prim[(t,i)]))
cases=['a1','a2','a3','a4','a5','a6','a7','a8','b1','b2','b3','b4','b5','c1','c2','c3','c4','c5','c6','d1','d2','d3','d4','d5','d6','d7','d8','e1','e2','e3','e4','t1','f1','f2','g1','j1','j2','j3','j4','j5','j6','j7']
print('case '+' '.join(t[:6].ljust(6) for t in tools))
for c in cases: print(c.ljust(5)+' '.join((''.join(sorted(cell.get((c,t),set()))) or '.').ljust(6)[:6] for t in tools))
EXP={'a1':'R','a2':'R','a3':'E','a4':'XE','a5':'EdE','a6':'D','a7':'R','a8':'R','b1':'R','b2':'R','b3':'R','b4':'E','b5':'R','c1':'R','c2':'RE','c4':'R','c6':'R','j1':'R','j2':'E','j3':'XE','j6':'R'}
def hit(c,t,exp): 
    s=cell.get((c,t),set()); return any(f in s for f in (['Ed','E'] if exp=='EdE' else (['X','E'] if exp=='XE' else (['R','E'] if exp=='RE' else [exp]))))
print('\nQV recall  canon(a1-a8) variants(b1-b5) 3rdparty(c1,c2,c4,c6) java(j1,j2,j3,j6) total/21')
for t in tools:
    g=lambda cs: sum(hit(c,t,EXP[c]) for c in cs)
    A=g(['a1','a2','a3','a4','a5','a6','a7','a8']);Bv=g(['b1','b2','b3','b4','b5']);C=g(['c1','c2','c4','c6']);J=g(['j1','j2','j3','j6'])
    print(f'{t:15s} {A}/8 {Bv}/5 {C}/4 {J}/4  {A+Bv+C+J}/21')
print('\nPQC named (K/S/P) in d1 d2 d4 d6 d7 j4 j5 ; FP cells e1 e2 g1 ; d3/d8 X flagged')
for t in tools:
    pq=[c for c in ['d1','d2','d4','d6','d7','j4','j5'] if cell.get((c,t),set())&{'K','S','P'}]
    fp=[c for c in ['e1','e2','g1'] if cell.get((c,t),set())-{'o'}]
    hy=[c for c in ['d3','d8'] if cell.get((c,t),set())&{'X','E'}]
    print(f'{t:15s} pqc={pq} fp={fp} hybridX={hy}')
json.dump({t:recs[t] for t in recs},open(R+'normalized2.json','w'),indent=0)

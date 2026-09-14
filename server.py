import base64, hashlib, hmac, json, os, secrets, sqlite3, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DB='gestor_maquinas.db'
TABLES=['machines','clients','maintenance','stock']
ADMIN_USER=os.environ.get('GESTOR_ADMIN_USER','julio')
ADMIN_PASSWORD=os.environ.get('GESTOR_ADMIN_PASSWORD','change-this-password')
TOKEN_SECRET=os.environ.get('GESTOR_TOKEN_SECRET','change-this-token-secret')

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.executescript('''CREATE TABLE IF NOT EXISTS machines(id INTEGER PRIMARY KEY AUTOINCREMENT, model TEXT, serial TEXT, client TEXT, counter INTEGER, status TEXT);
    CREATE TABLE IF NOT EXISTS clients(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, phone TEXT, location TEXT);
    CREATE TABLE IF NOT EXISTS maintenance(id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, machine TEXT, service TEXT, tech TEXT, status TEXT, notes TEXT);
    CREATE TABLE IF NOT EXISTS stock(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, compatibility TEXT, quantity INTEGER, minimum INTEGER);''')
    return c

def make_token(user):
    payload=f'{user}:{int(time.time())+86400}'
    sig=hmac.new(TOKEN_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f'{payload}:{sig}'.encode()).decode()

def valid_token(value):
    try:
        raw=base64.urlsafe_b64decode(value.encode()).decode(); user,expires,sig=raw.rsplit(':',2)
        payload=f'{user}:{expires}'
        return int(expires)>time.time() and hmac.compare_digest(sig,hmac.new(TOKEN_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest())
    except Exception: return False

class API(BaseHTTPRequestHandler):
    def headers(self):
        self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
    def send_json(self,data,code=200): self.send_response(code); self.headers(); self.end_headers(); self.wfile.write(json.dumps(data,ensure_ascii=False).encode())
    def authorized(self):
        value=self.headers.get('Authorization','')
        if not value.startswith('Bearer ') or not valid_token(value[7:]): self.send_json({'error':'Acesso não autorizado'},401); return False
        return True
    def do_OPTIONS(self): self.send_response(204); self.headers(); self.end_headers()
    def do_GET(self):
        if not self.authorized(): return
        table=urlparse(self.path).path.strip('/').split('/')[-1]
        if table not in TABLES: return self.send_json({'error':'Rota não encontrada'},404)
        c=db(); rows=[dict(r) for r in c.execute(f'SELECT * FROM {table} ORDER BY id DESC')]; c.close(); self.send_json(rows)
    def do_POST(self):
        route=urlparse(self.path).path.strip('/')
        size=int(self.headers.get('Content-Length',0) or 0); data=json.loads(self.rfile.read(size) or '{}')
        if route=='login':
            if hmac.compare_digest(str(data.get('user','')),ADMIN_USER) and hmac.compare_digest(str(data.get('password','')),ADMIN_PASSWORD): return self.send_json({'token':make_token(ADMIN_USER)})
            return self.send_json({'error':'Credenciais incorretas'},401)
        table=route.split('/')[-1]
        if not self.authorized(): return
        if table not in TABLES: return self.send_json({'error':'Rota não encontrada'},404)
        allowed={'machines':['model','serial','client','counter','status'],'clients':['name','phone','location'],'maintenance':['date','machine','service','tech','status','notes'],'stock':['name','compatibility','quantity','minimum']}[table]
        data={k:data.get(k,'') for k in allowed}; cols=','.join(data); vals=list(data.values()); q=','.join('?'*len(vals)); c=db(); cur=c.execute(f'INSERT INTO {table} ({cols}) VALUES ({q})',vals); c.commit(); data['id']=cur.lastrowid; c.close(); self.send_json(data,201)

if __name__=='__main__':
    if ADMIN_PASSWORD=='change-this-password' or TOKEN_SECRET=='change-this-token-secret': print('AVISO: configure GESTOR_ADMIN_PASSWORD e GESTOR_TOKEN_SECRET antes de publicar.')
    db().close(); print('Gestor Máquinas API: http://0.0.0.0:8080'); HTTPServer(('0.0.0.0',8080),API).serve_forever()

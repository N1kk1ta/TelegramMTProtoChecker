
import os, sys, subprocess, tempfile, shutil, urllib.request, urllib.parse, re, threading, webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

SOURCE_RAW="https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt"
SOURCE_PAGE="https://github.com/Grim1313/mtproto-for-telegram/blob/master/all_proxies.txt"

def resource_path(*parts):
    base=getattr(sys,"_MEIPASS",os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base,*parts)

def parse_proxy(line):
    line=line.strip()
    if not line or line.startswith("#"): return None
    try:
        u=urllib.parse.urlparse(line)
        if line.startswith("tg://proxy?") or "t.me/proxy?" in line:
            q=u.query
        else: return None
        p=urllib.parse.parse_qs(q)
        return {"url":line,"server":p["server"][0],"port":int(p["port"][0]),"secret":p["secret"][0]}
    except Exception:
        return None

def ptype(secret):
    s=secret.lower()
    if s.startswith("dd"): return "DD / Secure"
    if s.startswith("ee") or len(s)>32: return "Fake-TLS / EE"
    return "Normal"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Telegram Proxy Checker v5.8")
        self.geometry("1250x720")
        self.minsize(1000,580)
        self.proxies=[]; self.results=[]; self.running=False
        self.build()

    def build(self):
        b=ttk.Frame(self,padding=10); b.pack(fill="x")
        buttons=[
            ("Скачать свежий список",self.download),
            ("Загрузить TXT",self.load_file),
            ("Проверить MTProto",self.start),
            ("Сортировать по Ping",self.sort_ping),
            ("Открыть в Telegram",self.open_tg),
            ("Экспорт рабочих",self.export),
        ]
        for t,c in buttons: ttk.Button(b,text=t,command=c).pack(side="left",padx=3)
        o=ttk.Frame(self,padding=(10,0,10,8));o.pack(fill="x")
        ttk.Label(o,text="Timeout (мс):").pack(side="left")
        self.timeout=tk.IntVar(value=5000);ttk.Spinbox(o,from_=1000,to=30000,increment=500,textvariable=self.timeout,width=7).pack(side="left",padx=4)
        ttk.Label(o,text="Повторы:").pack(side="left",padx=(15,0))
        self.repeat=tk.IntVar(value=1);ttk.Spinbox(o,from_=1,to=5,textvariable=self.repeat,width=5).pack(side="left",padx=4)
        ttk.Label(o,text="DC:").pack(side="left",padx=(15,0))
        self.dc=tk.StringVar(value="-5,-4,-3,-2,-1,1,2,3,4,5")
        ttk.Entry(o,textvariable=self.dc,width=24).pack(side="left",padx=4)
        self.status=tk.StringVar(value="Готово");ttk.Label(o,textvariable=self.status).pack(side="right")

        cols=("status","ping","dc","server","port","proto","details","url")
        self.tree=ttk.Treeview(self,columns=cols,show="headings",selectmode="extended")
        heads={"status":"Статус","ping":"Ping","dc":"DC","server":"Сервер/IP","port":"Порт","proto":"Протокол","details":"Результаты MTProto","url":"TG-ссылка"}
        widths={"status":100,"ping":90,"dc":55,"server":220,"port":60,"proto":115,"details":390,"url":330}
        for c in cols:
            # ttk raises TclError when -command is explicitly passed as None.
            if c == "ping":
                self.tree.heading(c, text=heads[c], command=self.sort_ping)
            else:
                self.tree.heading(c, text=heads[c])
            self.tree.column(c,width=widths[c],anchor="center" if c in ("status","ping","dc","port") else "w")
        self.tree.pack(fill="both",expand=True,padx=10,pady=5)
        self.pb=ttk.Progressbar(self,mode="determinate");self.pb.pack(fill="x",padx=10)
        ttk.Label(self,text="Проверка выполняется через настоящий mtp_ping: MTProto req_pq/res_pq + Telegram ping. В v5 Erlang/OTP и mtp_ping упакованы внутрь одного EXE.",padding=10).pack(anchor="w")

    def set_lines(self,lines):
        seen=set(); self.proxies=[]
        for line in lines:
            p=parse_proxy(line)
            if p:
                k=(p["server"],p["port"],p["secret"])
                if k not in seen:
                    seen.add(k)
                    self.proxies.append(p)
        self.results=[]
        self.refresh_table()

    def refresh_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for p in self.proxies:
            self.tree.insert("", "end", values=(
                "⚪ Не проверен", "—", "—", p["server"], p["port"],
                ptype(p["secret"]), "Ожидает проверки", p["url"]))

    def download(self):
        def job():
            try:
                req=urllib.request.Request(SOURCE_RAW,headers={"User-Agent":"TelegramProxyChecker/5"})
                with urllib.request.urlopen(req,timeout=20) as r:data=r.read().decode("utf-8","replace")
                lines=data.splitlines()
                self.after(0, lambda lines=lines: self.set_lines(lines))
                count=sum(1 for line in lines if parse_proxy(line))
                self.after(0, lambda count=count: self.status.set(f"Загружено: {count} прокси"))
            except Exception as e:
                self.after(0, lambda e=e: self.status.set(f"Ошибка загрузки: {e}"))
        threading.Thread(target=job,daemon=True).start()

    def load_file(self):
        p=filedialog.askopenfilename(filetypes=[("TXT","*.txt"),("Все файлы","*.*")])
        if p:
            with open(p,encoding="utf-8",errors="replace") as f:self.set_lines(f)
            self.status.set(f"Загружено: {len(self.proxies)}")

    def mtp_command(self):
        # The build places the Erlang runtime and mtp_ping under bundled/.
        escript=resource_path("bundled","erlang","bin","escript.exe")
        mtp=resource_path("bundled","mtp_ping")
        if not os.path.exists(escript) or not os.path.exists(mtp):
            raise FileNotFoundError("В сборке отсутствуют Erlang runtime или mtp_ping.")
        return escript,mtp

    def check_one(self,p):
        escript,mtp=self.mtp_command()
        secret=p["secret"].lower()
        if secret.startswith("dd"):
            proto="secure"
        elif secret.startswith("ee"):
            proto="fake-tls"
        elif len(secret) > 32:
            # Base64-url Fake-TLS secrets do not necessarily start with ee.
            proto="fake-tls"
        else:
            proto="normal"
        cmd=[escript,mtp,"--proto",proto,"--dc",self.dc.get(),
             "--timeout",str(self.timeout.get()),"--repeat",str(self.repeat.get()),p["url"]]
        startupinfo=None
        creationflags=0
        if os.name == "nt":
            creationflags=subprocess.CREATE_NO_WINDOW
        env=os.environ.copy()
        # The bundled Erlang runtime is relocatable.  On Windows, make sure
        # escript/erl explicitly use the runtime shipped inside this EXE.
        erlang_root=resource_path("bundled","erlang")
        env["ERL_ROOTDIR"]=erlang_root
        env["ROOTDIR"]=erlang_root
        env["PATH"]=os.path.join(erlang_root,"bin")+os.pathsep+env.get("PATH","")
        for name in os.listdir(erlang_root) if os.path.isdir(erlang_root) else []:
            if name.startswith("erts-"):
                erts_bin=os.path.join(erlang_root,name,"bin")
                if os.path.isdir(erts_bin):
                    env["PATH"]=erts_bin+os.pathsep+env["PATH"]
                    break
        r=subprocess.run(cmd,capture_output=True,text=True,encoding="utf-8",errors="replace",
                         timeout=max(45,int(self.timeout.get()/1000)*30),
                         startupinfo=startupinfo,creationflags=creationflags,
                         cwd=os.path.dirname(mtp),env=env)
        text=(r.stdout or "")+(r.stderr or "")
        return self.parse_output(text),text

    def parse_output(self,text):
        # mtp_ping output:
        #   fake-tls   DC +1  : tcp=45ms handshake=52ms ping=140ms  [total=237ms]  OK
        rows=[]
        pat=re.compile(r'DC\s+([+-]?\d+)\s*:\s*.*?ping=(\d+)ms.*?(?:\[?total=(\d+)ms\]?.*?)?\b(OK|DISABLED)\b',re.I)
        for m in pat.finditer(text):
            rows.append((int(m.group(2)),int(m.group(1)),m.group(4).upper()=="OK",m.group(3)))
        if not rows:
            # Accept variants without total and with extra whitespace/newlines.
            pat=re.compile(r'DC\s+([+-]?\d+).*?ping\s*[=:]\s*(\d+)\s*ms.*?\b(OK|DISABLED)\b',re.I|re.S)
            for m in pat.finditer(text):
                rows.append((int(m.group(2)),int(m.group(1)),m.group(3).upper()=="OK",None))
        good=[x for x in rows if x[2]]
        if not good:
            # Keep the real tool error in the row instead of hiding it behind a generic popup.
            compact=" ".join(text.strip().split())
            if len(compact)>220: compact=compact[:220]+"…"
            return {"ok":False,"ping":None,"dc":None,
                    "details":compact or "MTProto handshake/ping failed"}
        good.sort(key=lambda x:x[0])
        details=" | ".join(f"DC{dc}: {ping} ms"+(f" (total {tot} ms)" if tot else "") for ping,dc,_,tot in good)
        return {"ok":True,"ping":good[0][0],"dc":good[0][1],"details":details}

    def start(self):
        if not self.proxies:messagebox.showwarning("Нет прокси","Сначала загрузите список.");return
        if self.running:return
        self.running=True;self.results=[]
        for i in self.tree.get_children():self.tree.delete(i)
        self.pb["maximum"]=len(self.proxies);self.pb["value"]=0
        threading.Thread(target=self.worker,daemon=True).start()

    def worker(self):
        for n,p in enumerate(self.proxies,1):
            try:r,raw=self.check_one(p)
            except Exception as e:r={"ok":False,"ping":None,"dc":None,"details":str(e)}
            self.results.append((p,r))
            self.after(0,self.add_row,p,r,n)
        self.running=False
        self.after(0,lambda:self.status.set(f"Готово: {sum(r['ok'] for _,r in self.results)} рабочих из {len(self.results)}"))

    def add_row(self,p,r,n):
        self.pb["value"]=n
        self.tree.insert("", "end",values=(
            "🟢 Работает" if r["ok"] else "🔴 Не работает",
            f"{r['ping']} ms" if r["ping"] is not None else "—",
            f"DC{r['dc']}" if r["dc"] is not None else "—",
            p["server"],p["port"],ptype(p["secret"]),r["details"],p["url"]))

    def sort_ping(self):
        rows=[]
        for i in self.tree.get_children():
            v=self.tree.item(i,"values")
            try:n=int(v[1].split()[0])
            except:n=10**9
            rows.append((n,i))
        for pos,(_,i) in enumerate(sorted(rows,key=lambda x:x[0])):self.tree.move(i,"",pos)

    def open_tg(self):
        s=self.tree.selection()
        if not s:return
        values=self.tree.item(s[0],"values")
        server,port,secret=values[3],values[4],values[7]
        # Always rebuild a canonical tg:// URI from parsed proxy data.
        p=parse_proxy(secret)
        if not p:
            self.status.set("Не удалось сформировать корректную Telegram-ссылку")
            return
        uri="tg://proxy?"+urllib.parse.urlencode(
            {"server":p["server"],"port":p["port"],"secret":p["secret"]},
            safe="-_.~="
        )
        try:
            if os.name=="nt":
                os.startfile(uri)
            else:
                webbrowser.open(uri)
            self.status.set("Ссылка передана в Telegram")
        except Exception as e:
            self.status.set(f"Ошибка открытия Telegram: {e}")

    def export(self):
        good=[p["url"] for p,r in self.results if r["ok"]]
        if not good:return
        p=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("TXT","*.txt")])
        if p:
            with open(p,"w",encoding="utf-8") as f:f.write("\n".join(good))
            messagebox.showinfo("Готово",f"Сохранено: {len(good)}")

if __name__=="__main__":App().mainloop()

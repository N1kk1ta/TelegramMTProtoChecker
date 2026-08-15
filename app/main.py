
import os, sys, subprocess, tempfile, shutil, urllib.request, urllib.parse, re, threading, webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont

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

def normalize_secret_for_mtp(secret):
    """Normalize Telegram MTProto secrets for the bundled mtp_ping.

    Important compatibility rule:
    Some public proxy lists contain Base64 secrets with extra garbage bytes
    appended to the end. Telegram clients may accept such links by trimming
    the value until a valid 16-byte secret remains. We do the same for the
    checker, but only after preserving the real Fake-TLS (0xEE) format.

    Canonical formats:
      - 32 hex chars: normal
      - dd + 32 hex chars: secure
      - ee + 32+ hex chars: fake-TLS
      - Base64/Base64URL -> decoded bytes:
          * starts EE: fake-TLS, keep the whole value
          * starts DD and has >=17 bytes: secure, use the next 16 bytes
          * otherwise: use the first 16 bytes as a normal secret; trailing
            bytes are treated as garbage added to the public link
    """
    import base64

    s=urllib.parse.unquote(str(secret or "")).strip().replace(" ", "+")
    if not s:
        raise ValueError("Пустой secret")

    # Canonical hexadecimal formats must be handled before generic Base64.
    # A 32-char hex secret can also look like Base64, but it is unambiguously
    # a normal MTProto secret unless it has an explicit dd/ee prefix.
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return s.lower()
    if re.fullmatch(r"dd[0-9a-fA-F]{32}", s, re.I):
        return s.lower()
    if re.fullmatch(r"ee[0-9a-fA-F]{32,}", s, re.I):
        return s.lower()

    # Base64/Base64URL. mtp_ping itself recognizes Fake-TLS Base64 by a
    # leading '7', but public lists are also known to contain malformed or
    # garbage-appended Base64 links. Decode first and validate the bytes here.
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s):
        raise ValueError("Некорректный формат secret")

    core=s.rstrip("=")
    if len(core) == 0 or len(core) % 4 == 1 or len(s) - len(core) > 2:
        raise ValueError("Некорректный Base64 secret")
    try:
        raw=base64.urlsafe_b64decode(core + "=" * ((-len(core)) % 4))
    except Exception as exc:
        raise ValueError("Некорректный Base64 secret") from exc

    if len(raw) < 16:
        raise ValueError(f"Некорректный Base64 secret: только {len(raw)} байт")

    # Real Fake-TLS: EE + 16-byte token + SNI/domain. Keep all bytes.
    if raw[0] == 0xEE:
        if len(raw) < 17:
            raise ValueError("Некорректный Fake-TLS secret: отсутствует secret")
        return raw.hex()

    # Secure transport: DD + 16-byte token. Ignore anything appended after
    # the canonical 17-byte form, if a public list has garbage after it.
    if raw[0] == 0xDD:
        return "dd" + raw[1:17].hex()

    # Compatibility with garbage-appended Base64 links. A normal MTProto
    # secret is exactly 16 bytes and may contain any byte values, including
    # EF. If more bytes follow and the value is not EE/DD, use the first 16
    # bytes as the actual secret and ignore the appended garbage.
    return raw[:16].hex()


def ptype(secret):
    s=urllib.parse.unquote(str(secret or "")).strip().replace(" ", "+")
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return "Normal"
    if re.fullmatch(r"dd[0-9a-fA-F]{32}", s, re.I):
        return "DD / Secure"
    if re.fullmatch(r"ee[0-9a-fA-F]{32,}", s, re.I):
        return "Fake-TLS / EE"
    if re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s):
        try:
            import base64
            core=s.rstrip("=")
            raw=base64.urlsafe_b64decode(core + "=" * ((-len(core)) % 4))
            if len(raw) >= 17 and raw[0] == 0xEE:
                return "Fake-TLS / Base64"
            if len(raw) >= 17 and raw[0] == 0xDD:
                return "DD / Secure / Base64"
            if len(raw) >= 16:
                return "Normal / Base64"
        except Exception:
            pass
    return "Некорректный secret"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Telegram Proxy Checker v5.19")
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
        self.timeout=tk.IntVar(value=150);ttk.Spinbox(o,from_=50,to=30000,increment=50,textvariable=self.timeout,width=7).pack(side="left",padx=4)
        ttk.Label(o,text="Повторы:").pack(side="left",padx=(15,0))
        self.repeat=tk.IntVar(value=1);ttk.Spinbox(o,from_=1,to=5,textvariable=self.repeat,width=5).pack(side="left",padx=4)
        ttk.Label(o,text="DC:").pack(side="left",padx=(15,0))
        self.dc=tk.StringVar(value="-5,-4,-3,-2,-1,1,2,3,4,5")
        ttk.Entry(o,textvariable=self.dc,width=24).pack(side="left",padx=4)
        self.status=tk.StringVar(value="Готово");ttk.Label(o,textvariable=self.status).pack(side="right")

        cols=("status","ping","dc","server","port","proto","details","url")
        # Таблица с вертикальной и горизонтальной прокруткой.
        table_frame=ttk.Frame(self)
        table_frame.pack(fill="both",expand=True,padx=10,pady=5)
        self.tree=ttk.Treeview(table_frame,columns=cols,show="headings",selectmode="extended")
        heads={"status":"Статус","ping":"Ping","dc":"DC","server":"Сервер/IP","port":"Порт","proto":"Протокол","details":"Результаты MTProto","url":"TG-ссылка"}
        widths={"status":100,"ping":90,"dc":55,"server":220,"port":60,"proto":115,"details":390,"url":330}
        for c in cols:
            # ttk raises TclError when -command is explicitly passed as None.
            if c == "ping":
                self.tree.heading(c, text=heads[c], command=self.sort_ping)
            else:
                self.tree.heading(c, text=heads[c])
            self.tree.column(c,width=widths[c],anchor="center" if c in ("status","ping","dc","port") else "w")
        vscroll=ttk.Scrollbar(table_frame,orient="vertical",command=self.tree.yview)
        hscroll=ttk.Scrollbar(table_frame,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=vscroll.set,xscrollcommand=hscroll.set)
        self.tree.grid(row=0,column=0,sticky="nsew")
        vscroll.grid(row=0,column=1,sticky="ns")
        hscroll.grid(row=1,column=0,sticky="ew")
        table_frame.rowconfigure(0,weight=1)
        table_frame.columnconfigure(0,weight=1)
        # TG-ссылка: ЛКМ открывает ссылку в Telegram, ПКМ копирует её в буфер обмена.
        self.tree.bind("<Button-1>", self.on_tree_left_click, add="+")
        self.tree.bind("<Button-3>", self.on_tree_right_click, add="+")
        self.tree.bind("<Double-Button-1>", self.on_tree_header_double_click, add="+")
        self.pb=ttk.Progressbar(self,mode="determinate");self.pb.pack(fill="x",padx=10)
        ttk.Label(self,text="Проверка выполняется через настоящий mtp_ping: MTProto req_pq/res_pq + Telegram ping. В v5.19 Erlang/OTP и mtp_ping упакованы внутрь одного EXE.",padding=10).pack(anchor="w")

    def get_item_tg_url(self, item_id):
        if not item_id:
            return None
        values=self.tree.item(item_id, "values")
        if not values or len(values) < 8:
            return None
        url=values[7]
        return str(url) if url else None

    def on_tree_left_click(self, event):
        # ЛКМ по результату MTProto копирует весь текст ячейки.
        # ЛКМ по TG-ссылке открывает ссылку в Telegram.
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        col=self.tree.identify_column(event.x)
        if col not in ("#7", "#8"):
            return
        item=self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        self.tree.focus(item)
        values=self.tree.item(item, "values")
        if col == "#7" and len(values) >= 7:
            text=str(values[6])
            if text:
                self.clipboard_clear()
                self.clipboard_append(text)
                self.update()
                self.status.set("Результат MTProto скопирован в буфер обмена")
        elif col == "#8":
            url=self.get_item_tg_url(item)
            if url:
                self.open_tg_url(url)
        return "break"

    def on_tree_header_double_click(self, event):
        # Двойной ЛКМ по заголовку/разделителю между колонками
        # автоматически подбирает ширину соответствующей колонки.
        if self.tree.identify_region(event.x, event.y) != "heading":
            return
        col=self.tree.identify_column(event.x)
        if not col or col == "#0":
            return
        try:
            idx=int(col[1:])-1
            column=self.tree["columns"][idx]
        except (ValueError, IndexError):
            return
        f=tkfont.nametofont("TkDefaultFont")
        heading=self.tree.heading(column, "text") or ""
        max_width=f.measure(str(heading)) + 24
        for item in self.tree.get_children(""):
            vals=self.tree.item(item, "values")
            if idx < len(vals):
                max_width=max(max_width, f.measure(str(vals[idx])) + 24)
        # Ограничиваем экстремально длинные строки, чтобы одна ошибка
        # не превращала таблицу в полосу на несколько тысяч пикселей.
        max_limits={"details":1200,"url":700,"server":500}
        max_width=min(max_width, max_limits.get(column, 500))
        self.tree.column(column, width=max(60, max_width))
        return "break"

    def on_tree_right_click(self, event):
        # ПКМ по TG-ссылке копирует полный URI, а не только видимый текст.
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#8":
            return
        item=self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        self.tree.focus(item)
        url=self.get_item_tg_url(item)
        if url:
            self.clipboard_clear()
            self.clipboard_append(url)
            self.update()
            self.status.set("TG-ссылка скопирована в буфер обмена")
        return "break"

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
        try:
            secret=normalize_secret_for_mtp(p["secret"])
        except ValueError as e:
            return {"ok":False,"ping":None,"dc":None,"details":str(e)}, str(e)
        # Rebuild the URL with the normalized secret. This converts only
        # verified MTProto Base64 formats to canonical hex; invalid Base64 is
        # rejected before mtp_ping is started.
        # 22-character unpadded Base64 form of a 16-byte normal MTProto secret
        # without changing the link stored/displayed in the table.
        parsed=urllib.parse.urlparse(p["url"])
        query=urllib.parse.urlencode({"server":p["server"],"port":str(p["port"]),"secret":secret})
        check_url=urllib.parse.urlunparse((parsed.scheme,parsed.netloc,parsed.path,parsed.params,query,parsed.fragment))
        dc_value=self.dc.get().strip()
        # mtp_ping uses a simple positional Erlang argument parser: --dc must
        # be a separate argument followed by its value. Do NOT use --dc=...
        # because it is treated as an unknown option (especially for negative DCs).
        cmd=[escript,mtp]
        if dc_value:
            cmd += ["--dc",dc_value]
        # Explicitly select the protocol after normalization. This is important
        # because mtp_ping itself uses a leading '7' heuristic for Base64; a
        # perfectly valid normal hex secret can also begin with '7'. Passing
        # --proto removes that ambiguity.
        normalized_lower=secret.lower()
        if normalized_lower.startswith("dd") and re.fullmatch(r"dd[0-9a-f]{32}", normalized_lower):
            proto_arg="secure"
        elif normalized_lower.startswith("ee") and re.fullmatch(r"ee[0-9a-f]+", normalized_lower):
            proto_arg="fake-tls"
        else:
            proto_arg="normal"
        cmd += ["--proto",proto_arg,"--timeout",str(self.timeout.get()),"--repeat",str(self.repeat.get()),check_url]
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
            # Не показываем пользователю многострочную справку mtp_ping.
            # Извлекаем реальную причину (например, invalid secret length).
            compact=" ".join(text.strip().split())
            err_match=re.search(r'Error:\s*(.+?)(?:\s+Usage:|$)', compact, re.I)
            if err_match:
                compact=err_match.group(1).strip()
            elif "Usage: mtp_ping" in compact:
                # Если текущий mtp_ping не дал отдельного Error:, считаем URL
                # некорректным, а не выдаём пользователю страницу Usage.
                compact="Некорректная MTProto-ссылка или secret"
            if len(compact)>300: compact=compact[:300]+"…"
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
        self.after(0,self.sort_ping)
        self.after(0,lambda:self.status.set(f"Готово: {sum(r['ok'] for _,r in self.results)} рабочих из {len(self.results)}. Отсортировано по Ping"))

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

    def open_tg_url(self, url):
        # Always rebuild a canonical tg:// URI from parsed proxy data.
        p=parse_proxy(url)
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

    def open_tg(self):
        s=self.tree.selection()
        if not s:return
        url=self.get_item_tg_url(s[0])
        if url:
            self.open_tg_url(url)

    def export(self):
        good=[p["url"] for p,r in self.results if r["ok"]]
        if not good:return
        p=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("TXT","*.txt")])
        if p:
            with open(p,"w",encoding="utf-8") as f:f.write("\n".join(good))
            messagebox.showinfo("Готово",f"Сохранено: {len(good)}")

if __name__=="__main__":App().mainloop()

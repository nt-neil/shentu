"""S8 driver: two questions in one `shentu chat` session. Every confirmation prompt is answered n,
so a model that proposes an action does not swallow the second question.
Usage: python3 -I s8.py <out-file>"""
import os, pty, select, sys, time

Q = ["最近 SSH 暴力破解次數最多的是哪一個 IP？", "那個 IP 嘗試登入了哪些帳號名稱？"]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("shentu", ["shentu", "chat"])
out, buf, asked, deadline = open(sys.argv[1], "w"), "", 0, time.time() + 900
def send(s):
    time.sleep(0.3); os.write(fd, (s + "\r").encode())
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1)
    if r:
        try: data = os.read(fd, 4096).decode("utf-8", "replace")
        except OSError: break
        if not data: break
        out.write(data); out.flush(); buf += data
    if "Allow? [y/N]" in buf:
        buf = ""; send("n")
    elif buf.rstrip().endswith(">"):
        buf = ""
        if asked < len(Q):
            out.write("\n> "); send(Q[asked]); asked += 1
        else:
            send("exit"); break
out.close()
os.waitpid(pid, 0)

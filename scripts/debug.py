import os
import json
import site
import socket
import argparse
from signal import SIGKILL
from pathlib import Path
from time import sleep

from libtmux import Server, Window, Session

t: Server = Server()
s: Session = t.sessions[0]


def start(name, module, cwd, /, *args, port: int = 25555):
    w: Window | None = s.find_where({"window_name": name})

    if w:
        w.kill_window()

    cmd = "tmux set remain-on-exit on"
    w = s.new_window(
        window_name=name,
        window_shell=cmd,
        start_directory=cwd,
    )
    sleep(1)
    d = ["python3", "-m", "debugpy"]
    do = ["--listen", f"localhost:{port}", "--wait-for-client", "-m"]
    env = ["-e", f"PYTHONPATH={cwd}:{site.USER_SITE}/pdm/pep582:{site.USER_SITE}"]
    w.attached_pane.cmd("respawn-pane", *env, *d, *do, module, "--", *args)


def stop(name):
    w: Window | None = s.find_where({"window_name": name})

    if not w:
        return

    try:
        os.kill(int(w.attached_pane.pid), SIGKILL)
    except ProcessLookupError:
        pass


parser = argparse.ArgumentParser()
parser.add_argument("--config", dest="config", required=True)
parser.add_argument("--cwd", dest="cwd", required=True)
parser.add_argument("--start", action="store_true")
parser.add_argument("--stop", action="store_true")
cli_args = parser.parse_args()

config = json.load(Path(cli_args.config).open("r"))

name = f"dpy: {config.get('name', config['port'])}"
module = config.get("module")
cwd = cli_args.cwd
args = config.get("args")
port = config.get("port", 25555)

if cli_args.start:
    start(name, module, cwd, *args, port=port)
elif cli_args.stop:
    stop(name)
else:
    raise SystemExit("You should either start or stop")

sleep(1)

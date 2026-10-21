"""Linux process-control regression tests, only inside pytest temporary directories."""

import json
import subprocess
import sys

from aegis.lab_runner.engine import MARKER_PROGRAM


def test_child_refuses_stale_parent_identity_before_creating_artifacts(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(MARKER_PROGRAM)],
        input=json.dumps({"marker": "aegis-test", "parent_pid": 0}),
        text=True,
        cwd=tmp_path,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode != 0
    assert not list(tmp_path.iterdir())


def test_parent_sigkill_kills_child_and_subreaper_collects_it(tmp_path):
    # Fixed program copy waits after installing PDEATHSIG; never available via runner API.
    child = tmp_path / "child_fixture.py"
    source = MARKER_PROGRAM.read_text().replace(
        "    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))",
        "    open('bound', 'w').close()\n    __import__('time').sleep(60)\n    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))",
    )
    child.write_text(source)
    parent = tmp_path / "parent_fixture.py"
    parent.write_text("""import json,os,subprocess,sys,time
p=subprocess.Popen([sys.executable,'-I','-S',sys.argv[1]],stdin=subprocess.PIPE)
p.stdin.write(json.dumps({'parent_pid':os.getpid(),'marker':'aegis-test'}).encode());p.stdin.close()
print(p.pid,flush=True)
time.sleep(60)
""")
    reaper = tmp_path / "reaper_fixture.py"
    reaper.write_text("""import ctypes,json,os,signal,subprocess,sys,time
libc=ctypes.CDLL(None)
assert libc.prctl(36,1,0,0,0)==0
p=subprocess.Popen([sys.executable,'-I','-S',sys.argv[1],sys.argv[2]],stdout=subprocess.PIPE,text=True)
child=int(p.stdout.readline())
try:
    end=time.monotonic()+3
    while not os.path.exists('bound'):
        assert time.monotonic()<end
        time.sleep(.01)
    p.kill();p.wait(timeout=1)
    end=time.monotonic()+2
    while time.monotonic()<end:
        pid,status=os.waitpid(child,os.WNOHANG)
        if pid:
            print(json.dumps({'signal':os.WTERMSIG(status)}));sys.exit(0)
        time.sleep(.01)
    raise RuntimeError('Child survived parent death')
finally:
    if p.poll() is None:p.kill();p.wait()
    try:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
    except (ProcessLookupError,ChildProcessError):pass
""")
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(reaper), str(parent), str(child)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=7,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["signal"] == 9

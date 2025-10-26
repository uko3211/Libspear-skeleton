import subprocess
import threading
import queue
import time
from typing import Optional, Dict
from llm_interface import LLMInterface

class InteractiveProcess:
    def __init__(self, cmd: list, cwd: Optional[str] = None, max_output_chars: int = 10000, read_chunk_size: int = 1024):
        self.cmd = cmd
        self.cwd = cwd
        self.max_output_chars = max_output_chars
        self.read_chunk_size = read_chunk_size
        self.proc: Optional[subprocess.Popen] = None
        self._stdout_q = queue.Queue()
        self._stdout_collected = []
        self._reader_thread: Optional[threading.Thread] = None
        self._alive = False

    def start(self, env: Optional[dict] = None):
        if self._alive:
            raise RuntimeError("Process already running")
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=self.cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env
        )
        self._alive = True
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    def _reader_loop(self):
        assert self.proc and self.proc.stdout
        try:
            while True:
                chunk = self.proc.stdout.read(self.read_chunk_size)
                if chunk == "":
                    break
                self._stdout_collected.append(chunk)
                total_len = sum(len(s) for s in self._stdout_collected)
                if total_len > self.max_output_chars:
                    joined = "".join(self._stdout_collected)
                    self._stdout_collected = [joined[-self.max_output_chars:]]
                self._stdout_q.put(chunk)
            self._alive = False
        except Exception as e:
            self._stdout_q.put(f"\n[READER ERROR] {e}\n")
            self._alive = False

    def send_input(self, s: str, newline: bool = True):
        if not self.proc or self.proc.stdin is None:
            raise RuntimeError("Process not started or stdin closed")
        data = s + ("\n" if newline else "")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except BrokenPipeError:
            raise RuntimeError("Broken pipe - process may have exited")

    def read_now(self, timeout: float = 0.1) -> str:
        parts = []
        start = time.time()
        while True:
            try:
                chunk = self._stdout_q.get(timeout=timeout)
                parts.append(chunk)
                while True:
                    try:
                        chunk = self._stdout_q.get_nowait()
                        parts.append(chunk)
                    except queue.Empty:
                        break
                break
            except queue.Empty:
                break
        return "".join(parts)

    def read_until(self, marker: str, timeout: float = 5.0) -> str:
        buf = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self.read_now(timeout=0.2)
            if chunk:
                buf.append(chunk)
                if marker in "".join(buf):
                    return "".join(buf)
            else:
                time.sleep(0.05)
        return "".join(buf)

    def get_collected_output(self) -> str:
        return "".join(self._stdout_collected)

    def is_alive(self) -> bool:
        if not self.proc:
            return False
        return self.proc.poll() is None

    def terminate(self, wait_sec: float = 2.0):
        if not self.proc:
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=wait_sec)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        finally:
            self._alive = False

llm = LLMInterface()

runner = InteractiveProcess(["python", "main.py","--mode","interactive"], cwd=".", max_output_chars=8000)
runner.start()
time.sleep(0.2)
initial_output = runner.read_now()
print(initial_output)

while runner.is_alive():
    prompt = f"Program output so far:\n{runner.get_collected_output()}\n\nWhat should we input next?"
    user_input = llm.generate_text(prompt)
    runner.send_input(user_input.strip())
    time.sleep(0.2)
    new_output = runner.read_now()
    print(new_output)

runner.terminate()
final_output = runner.get_collected_output()
summary_prompt = f"The final output of the program is:\n{final_output}\nSummarize it in 2 sentences."
summary = llm.generate_text(summary_prompt)
print("\n=== SUMMARY ===\n", summary)

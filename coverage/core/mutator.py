# coverage/core/mutator.py
import random
import string
import sys
import select
import termios
import tty

def mutate_string(s: str) -> str:
    if not s:
        return random.choice(string.ascii_lowercase)
    idx = random.randint(0, len(s) - 1)
    char = random.choice(string.ascii_lowercase + string.digits + "!@#$%^&*()")
    return s[:idx] + char + s[idx + 1:]

def get_single_char():
    try:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.cbreak(fd)
        ch = sys.stdin.read(1)
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch
    except:
        import msvcrt
        return msvcrt.getch().decode('utf-8')

def interactive_mode():
    print("Interactive Fuzzing Mode")
    
    current_input = ""
    
    try:
        while True:
            print(f"\n현재 입력: '{current_input}'")
            print("글자 입력 (ESC=종료): ", end="", flush=True)
            
            char = get_single_char()
            
            # ESC 키 또는 Ctrl+C로 종료
            if ord(char) == 27:  # ESC
                break
            
            if char == '\n' or char == '\r':
                # Enter 키: 현재 문자열을 변형해서 출력
                if current_input:
                    mutated = mutate_string(current_input)
                    print(f"\n원본: {current_input}")
                    print(f"변형: {mutated}")
                    return mutated
                continue
            
            if char == '\b' or char == '\x7f':  # Backspace
                if current_input:
                    current_input = current_input[:-1]
                    print('\b \b', end="", flush=True)
                continue
            
            # 일반 문자 추가
            if char.isprintable():
                current_input += char
                print(char, end="", flush=True)
                
                # 한 글자 입력할 때마다 즉시 변형
                mutated = mutate_string(current_input)
                print(f"\n실시간 변형: {mutated}")
    
    except KeyboardInterrupt:
        print("\n종료합니다.")
    
    return current_input

def mutate(input_str: str) -> str:
    return input_str

def _read_all_from_stdin() -> str:
    if sys.stdin is None:
        return ""
    try:
        return sys.stdin.read()
    except Exception:
        return ""


if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_str = sys.argv[1]
        print(mutate(input_str))
    else:
        if sys.stdin is not None and not sys.stdin.isatty():
            buffered_input = _read_all_from_stdin().strip()
            print(mutate(buffered_input))
        else:
            interactive_mode()

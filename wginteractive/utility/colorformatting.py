# required esc sequence --v   v-- color code
#                       \033[37mSomething happened!\033[m
#                              ^-- end of sequence  ^
#                                                   |
#           reset sequence (same as the beginning, without a code)

class AnsiEscapeCode:
    ESC = "\033["
    RESET = "\033[0m"
    FG_WHITE = "97"
    FG_RED = "31"
    FG_GREEN = "32"
    BOLD = "1"
    
def bold(text: str):
    return _format(text, AnsiEscapeCode.BOLD)

def red(text: str):
    return _format(text, AnsiEscapeCode.FG_RED)

def green(text: str):
    return _format(text, AnsiEscapeCode.FG_GREEN)

def _format(text: str, esc_sequence: str):
    return f"{AnsiEscapeCode.ESC}{esc_sequence}m{text}{AnsiEscapeCode.RESET}"

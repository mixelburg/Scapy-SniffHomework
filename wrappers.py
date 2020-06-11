try:
    from colorama import init, Fore
except:
    print("You have to install colorama. just run: pip install colorama")
# initialize colorama
init()
# define colors
RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET


def make_green(func):
    def wrapper(*args, **kwargs):
        print(GREEN)
        rv = func(*args, **kwargs)
        print(RESET)
        return rv
    return wrapper


def make_blue(func):
    def wrapper(*args, **kwargs):
        print(BLUE)
        rv = func(*args, **kwargs)
        print(RESET)
        return rv
    return wrapper


def make_red(func):
    def wrapper(*args, **kwargs):
        print(RED)
        rv = func(*args, **kwargs)
        print(RESET)
        return rv
    return wrapper


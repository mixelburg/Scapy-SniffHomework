import myLib

myLib.install_check()

try:
    import scapy
    from scapy.layers.dns import DNS, DNSRR
    from scapy.layers.http import HTTPRequest, HTTP
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.packet import Raw
    from scapy.sendrecv import sniff
except:
    print("You have to install scapy. just run: pip install scapy")

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

WEATHER_SERVER_IP = '34.218.16.79'
ANSWER_CODE = 'ANSWER'
EXIT_CHOICE = 0


def weather_parser(data):
    """
    parses data from weather server
    :param data: data from server
    :return: parsed data
    """
    data = data.split(':')
    weather_info = data[2].split('&')

    weather_parsed = {}
    for info in weather_info:
        info = info.split('=')
        weather_parsed[info[0]] = info[1]

    return weather_parsed


# checkers

def dns_checker(packet):
    return DNS in packet and DNSRR in packet


def weather_checker(packet):
    return IP in packet and \
           (packet[IP].src == WEATHER_SERVER_IP) and \
           (Raw in packet) and \
           (ANSWER_CODE in packet[Raw].load.decode())


def http_request_checker(packet):
    return HTTPRequest in packet


# printers

def print_dns(packet):
    """
    prints DNS packet
    :param packet:
    :return: None
    """
    if type(packet[DNSRR].rdata) != str:
        request_data = packet[DNSRR].rdata.decode()
    else:
        request_data = packet[DNSRR].rdata

    print(f"""{GREEN}
    Domain: {packet[DNSRR].rrname.decode()}
    Ip: {request_data} {RESET}""")


def print_weather(packet):
    """
    Prints weather from server
    :param packet:
    :return: None
    """
    data = packet[Raw].load.decode()
    info = weather_parser(data)

    print(f"""{GREEN}
    date: {info['date']}
    Temp in {info['city']} is: {info['temp']} degrees  
    situation: {info['text']}
    {RESET}""")


def print_http_request(packet):
    """
    Prints info from http request
    :param packet:
    :return: None
    """
    print(f"""
    {GREEN} 
    getting: {packet[HTTP].Path.decode()}
    host: {packet[HTTP].Host.decode()}
    {RESET}
    """)


class Switcher(object):
    """
    Simple switch-case implementation in python
    """
    def indirect(self, i):
        method_name = 'option_' + str(i)
        method = getattr(self, method_name, lambda: 'Invalid')
        return method()

    def option_1(self):
        print(f"{BLUE}[+] Started sniffing DNS{RESET}")
        sniff(lfilter=dns_checker, prn=print_dns)

    def option_2(self):
        print(f"{BLUE}[+] Started sniffing Weather{RESET}")
        sniff(lfilter=weather_checker, prn=print_weather)

    def option_3(self):
        print(f"{BLUE}[+] Started sniffing HTTP Requests{RESET}")
        sniff(lfilter=http_request_checker, prn=print_http_request)


def check_input(user_choice):
    # validates user input
    return 0 <= user_choice <= 3


def get_input():
    """
    gets input from user
    :return: user's input
    """
    choice = -1

    while not check_input(choice):
        try:
            choice = int(input("Enter your choice: "))
        except:
            print(f"{RED}[!] Only numbers allowed!{RESET}")

    return choice


def menu():
    print("""
    0: exit
    1: Sniff DNS
    2: Sniff Weather
    3: Sniff HTTP Requests
    """)


def hello():
    print(f"""{GREEN}
    
___  ___                _     _               _                _    
|  \/  |               | |   (_)             | |              | |   
| .  . | __ _  __ _ ___| |__  _ _ __ ___  ___| |__   __ _ _ __| | __
| |\/| |/ _` |/ _` / __| '_ \| | '_ ` _ \/ __| '_ \ / _` | '__| |/ /
| |  | | (_| | (_| \__ \ | | | | | | | | \__ \ | | | (_| | |  |   < 
\_|  |_/\__,_|\__, |___/_| |_|_|_| |_| |_|___/_| |_|\__,_|_|  |_|\_\\
               __/ |                                                
              |___/                                                 
Created by: Mixelburg!
    {RESET}""")


def main():
    hello()
    menu()

    choice = get_input()
    s = Switcher()

    while choice != EXIT_CHOICE:
        s.indirect(choice)
        menu()
        choice = get_input()


if __name__ == '__main__':
    main()

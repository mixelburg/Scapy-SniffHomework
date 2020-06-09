import os
import subprocess
import sys


def installer(packages):
    """
    Installs all 'packages' if you decide so
    :param packages:
    :return: None
    """
    print("Following packages no installed: ", end='')
    for package in packages:
        print(f" {package},", end='')
    print()

    choise = input("Would you like to install them? (Y/N): ")
    if choise.lower() == 'y':
        for package in packages:
            os.system(f'cmd /c "pip install {package}"')


def install_check():
    """
    Checks what packages do you have installed
    and warns you if required packages are missing
    if so, calls function 'installer'
    :return: None
    """
    reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'])
    installed_packages = [r.decode().split('==')[0] for r in reqs.split()]

    not_installed_packages = []
    if 'scapy' not in installed_packages:
        not_installed_packages.append('scapy')
    if 'colorama' not in installed_packages:
        not_installed_packages.append('colorama')

    if len(not_installed_packages) != 0:
        installer(not_installed_packages)
#!/usr/bin/env python3

# Import necessary modules
from art import text2art
from colorama import Fore, Style, init
import random
import nmap
import platform
import os
import socket
import subprocess
import webbrowser

# Initialize colorama for Windows (optional under Linux)
init()

# Define available colors
colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE]

# Generate the text "Kalisti" in gothic style
ascii_art_text = text2art("Kalisti", font="gothic")

# Apply a random color to each character of the ASCII text
colored_text = "".join(random.choice(colors) + char if char not in " \n" else char for char in ascii_art_text)
colored_text += Style.RESET_ALL

# Display the stylized and colored text
print(colored_text)

# Define commands with placeholder texts
commands = {
    1: "Start an Nmap scan",
    2: "Stop a service",
    3: "Restart a service",
    4: "Check system status",
    5: "System settings",
    6: "Display system info",
    7: "Show help",
    8: "Update the system",
    9: "Display event log",
    10: "Check network connections",
    11: "Monitor packets (tcpdump)",
    12: "Open ipinfo.io",
    13: "Open VirusTotal",
    14: "Open Shodan",
    15: "Open Censys",
    16: "Open ipkiller",
    17: "Open crt.sh",
    18: "Open Intelligence X",
    19: "Open OSINT Framework",
    20: "Open Have I Been Pwned",
    21: "Quit"
}

# Function to display commands across multiple pages
def display_commands_page(page_number):
    commands_per_page = 10
    command_list = list(commands.items())
    total_pages = (len(command_list) + commands_per_page - 1) // commands_per_page

    print(f"\n--- Page {page_number}/{total_pages} ---")
    print("=" * 60)

    start_index = (page_number - 1) * commands_per_page
    end_index = min(start_index + commands_per_page, len(command_list))

    for i in range(start_index, end_index):
        print(f"{random.choice(colors)}{i + 1}. {command_list[i][1]}{Style.RESET_ALL}")

    print("=" * 60)

    if page_number < total_pages:
        print("Press 'n' for the next page.")
    if page_number > 1:
        print("Press 'p' for the previous page.")
    print("Press 'q' to quit.")

# Function to print results in red
def print_red(text):
    print(Fore.RED + text + Style.RESET_ALL)

# Function to handle command execution errors
def execute_and_capture(command):
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print_red(f"Error executing command: {e.stderr.decode().strip()}")
        return None

# Prepare actions related to the commands
def execute_command(command_number):
    if command_number == 1:
        target = input("Enter the IP address or domain to scan: ")
        nm = nmap.PortScanner()
        print_red(f"Starting Nmap scan on {target}...")
        nm.scan(target)
        print(nm.all_info())
    elif command_number in (2, 3):
        action = "stop" if command_number == 2 else "restart"
        service_name = input(f"Enter the name of the service to {action}: ")
        execute_and_capture(["sudo", "systemctl", action, service_name])
        print_red(f"Service {service_name} {action}ed.")
    elif command_number == 4:
        print_red("System Information:")
        print_red(f"Operating System: {platform.system()} {platform.release()}")
        print_red(f"Hostname: {socket.gethostname()}")
    elif command_number == 5:
        os.system("sudo nano /etc/sysctl.conf")
    elif command_number == 6:
        print_red("System Information:")
        print_red(f"System: {platform.system()} {platform.release()}")
        print_red(f"Architecture: {platform.architecture()[0]}")
        print_red(f"Hostname: {socket.gethostname()}")
        print_red(f"Local IP: {socket.gethostbyname(socket.gethostname())}")
        print_red(f"Connected Users:\n{execute_and_capture(['who'])}")
    elif command_number == 7:
        print_red("Help:")
        print_red("1. Start an Nmap scan to discover open ports.")
        print_red("10. Check active network connections.")
        print_red("11. Monitor network packets with tcpdump.")
    elif command_number == 8:
        print_red("Updating the system...")
        execute_and_capture(["sudo", "apt", "update", "-y"])
        execute_and_capture(["sudo", "apt", "upgrade", "-y"])
    elif command_number == 9:
        print_red("Event Log:")
        print(execute_and_capture(["journalctl", "-xe"]))
    elif command_number == 10:
        print_red("Active network connections:")
        print(execute_and_capture(["netstat", "-tuln"]))
    elif command_number == 11:
        print_red("Monitoring network packets with tcpdump (press Ctrl+C to stop)...")
        os.system("sudo tcpdump")  # Monitor packets (requires sudo)
    elif command_number in range(12, 21):
        urls = [
            "https://ipinfo.io",
            "https://www.virustotal.com",
            "https://www.shodan.io",
            "https://censys.io",
            "https://ipkiller.com",
            "https://crt.sh",
            "https://intelx.io",
            "https://osintframework.com",
            "https://haveibeenpwned.com",
        ]
        webbrowser.open(urls[command_number - 12])
    elif command_number == 21:
        print_red("Exiting the program...")
        exit()
    else:
        print_red("Unrecognized command.")

def choose_action():
    current_page = 1
    total_pages = (len(commands) + 9) // 10

    while True:
        display_commands_page(current_page)

        user_input = input("Your choice or navigation (n/p/q): ").strip().lower()

        if user_input == 'n':
            if current_page < total_pages:
                current_page += 1
            else:
                print_red("You are already on the last page.")
        elif user_input == 'p':
            if current_page > 1:
                current_page -= 1
            else:
                print_red("You are already on the first page.")
        elif user_input == 'q':
            print_red("Exiting the program...")
            exit()
        else:
            try:
                choice = int(user_input)
                if 1 <= choice <= len(commands):
                    execute_command(choice)
                else:
                    print_red("Please enter a valid number.")
            except ValueError:
                print_red("Please enter a valid option.")

# Call the function to ask the user for their action
choose_action()

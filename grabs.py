import shodan
import threading
import queue
import os
import re
import time
import socket
from colorama import init, Fore, Style

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY_HERE"  # <-- Put your Shodan API key here

init(autoreset=True)
LIME = Fore.LIGHTGREEN_EX

banner = f"""{LIME}{Style.BRIGHT}
╔════════════════════════════════════════════════════════╗
║                                                        ║
║              Laravel Grabber By Bob Marley             ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
print(banner)

print(f"{LIME}{Style.BRIGHT}How To Use:")
print(f"{LIME}{Style.BRIGHT}1. Put your Shodan API key in the SHODAN_API_KEY variable at the top of the script.")
print(f"{LIME}{Style.BRIGHT}2. Run the script and follow the prompts.\n{Style.RESET_ALL}")

def is_ip(address):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address) is not None

def shodan_search_worker(api_key, query, page_queue, result_set, lock, total, progress):
    api = shodan.Shodan(api_key)
    while True:
        try:
            page = page_queue.get_nowait()
        except queue.Empty:
            break
        try:
            results = api.search(query, page=page)
            with lock:
                for match in results['matches']:
                    hostnames = match.get('hostnames', [])
                    for hostname in hostnames:
                        if not is_ip(hostname) and len(result_set) < total:
                            result_set.add(hostname)
                progress[0] = len(result_set)
                percent = int((progress[0] / total) * 100)
                bar = ('#' * (percent // 2)).ljust(50)
                print(f"\r{Fore.CYAN}Progress: [{bar}] {percent}% ({progress[0]}/{total}){Style.RESET_ALL}", end="")
        except Exception as e:
            print(f"{Fore.RED}Shodan error on page {page}: {e}{Style.RESET_ALL}")
        page_queue.task_done()
        time.sleep(1)  # Respect Shodan's rate limit

def shodan_reverse_ip_worker(api_key, ip_queue, shodan_results, rdns_queue, lock):
    api = shodan.Shodan(api_key)
    while True:
        try:
            ip = ip_queue.get_nowait()
        except queue.Empty:
            break
        if not is_ip(ip):
            continue
        found = False
        try:
            result = api.host(ip)
            hostnames = result.get('hostnames', [])
            with lock:
                for h in hostnames:
                    if (not is_ip(h) or ip in h) and h:
                        shodan_results.add(h)
                        found = True
        except Exception:
            pass
        if not found:
            rdns_queue.put(ip)
        time.sleep(1)  # Respect Shodan's rate limit

def rdns_worker(rdns_queue, rdns_results, lock):
    while True:
        try:
            ip = rdns_queue.get_nowait()
        except queue.Empty:
            break
        try:
            rdns = socket.gethostbyaddr(ip)[0]
            with lock:
                if rdns:
                    rdns_results.add(rdns)
        except Exception:
            pass

def domain_to_ip_worker(domain_queue, result_list, lock):
    while True:
        try:
            domain = domain_queue.get_nowait()
        except queue.Empty:
            break
        try:
            ip = socket.gethostbyname(domain)
            with lock:
                result_list.append(ip)
        except Exception:
            pass  # Skip domains that can't be resolved

def grab_domains():
    while True:
        try:
            num = int(input(f"{Fore.YELLOW}How much sites you want to grab (10-10000): {Style.RESET_ALL}"))
            if 10 <= num <= 10000:
                break
            else:
                print(f"{Fore.RED}Please enter a number between 10 and 10000.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}Shodan API allows only 1 request per second. Thread count is set to 1 for compliance.{Style.RESET_ALL}")
    num_threads = 1  # Force to 1 to avoid rate limit

    query = 'http.title:"Whoops! There was an error."'
    print(f"{Fore.LIGHTGREEN_EX}Searching Shodan for Laravel debug pages...{Style.RESET_ALL}")

    result_set = set()
    lock = threading.Lock()
    progress = [0]

    page_queue = queue.Queue()
    pages_needed = (num // 100) + 5
    for i in range(1, pages_needed + 1):
        page_queue.put(i)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=shodan_search_worker, args=(SHODAN_API_KEY, query, page_queue, result_set, lock, num, progress))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print()  # Newline after progress bar

    result_dir = "ResultGrab"
    os.makedirs(result_dir, exist_ok=True)
    output_path = os.path.join(result_dir, "Results.txt")

    with open(output_path, "w") as f:
        for site in list(result_set)[:num]:
            print(site)
            f.write(site + "\n")
    print(f"{Fore.LIGHTGREEN_EX}Saved {min(len(result_set), num)} domains to {output_path}{Style.RESET_ALL}")

def reverse_ip_to_domain():
    ip_file = input(f"{Fore.YELLOW}Enter the path to your IP list (e.g., ips.txt): {Style.RESET_ALL}").strip()
    print(f"{Fore.YELLOW}Shodan API allows only 1 request per second. Shodan lookups are single-threaded, but reverse DNS is parallelized for speed.{Style.RESET_ALL}")

    try:
        with open(ip_file, "r") as f:
            all_lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Failed to read IP list: {e}{Style.RESET_ALL}")
        return

    ips = [ip for ip in all_lines if is_ip(ip)]
    if not ips:
        print(f"{Fore.RED}No valid IPv4 addresses found in your input file. Please provide a list of IP addresses.{Style.RESET_ALL}")
        return

    ip_queue = queue.Queue()
    for ip in ips:
        ip_queue.put(ip)

    shodan_results = set()
    rdns_queue = queue.Queue()
    rdns_results = set()
    lock = threading.Lock()

    # Shodan lookups (single-threaded, rate-limited)
    shodan_thread = threading.Thread(target=shodan_reverse_ip_worker, args=(SHODAN_API_KEY, ip_queue, shodan_results, rdns_queue, lock))
    shodan_thread.start()
    shodan_thread.join()

    # Reverse DNS lookups (multi-threaded)
    rdns_threads = []
    rdns_thread_count = 10  # You can adjust this for more/less parallelism
    for _ in range(rdns_thread_count):
        t = threading.Thread(target=rdns_worker, args=(rdns_queue, rdns_results, lock))
        t.start()
        rdns_threads.append(t)
    for t in rdns_threads:
        t.join()

    result_dir = "ResultReverse"
    os.makedirs(result_dir, exist_ok=True)
    output_path = os.path.join(result_dir, "Reverse.txt")

    all_domains = sorted(set(list(shodan_results) + list(rdns_results)))

    with open(output_path, "w") as f:
        for h in all_domains:
            print(h)
            f.write(h + "\n")
    if all_domains:
        print(f"{Fore.LIGHTGREEN_EX}Saved reverse IP results to {output_path}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No domains found for the provided IPs. Output file is empty.{Style.RESET_ALL}")

def domain_to_ip():
    domain_file = input(f"{Fore.YELLOW}Enter the path to your domain list (e.g., domains.txt): {Style.RESET_ALL}").strip()
    while True:
        try:
            num_threads = int(input(f"{Fore.YELLOW}Thread (1-10): {Style.RESET_ALL}"))
            if 1 <= num_threads <= 10:
                break
            else:
                print(f"{Fore.RED}Please enter a number between 1 and 10.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")

    try:
        with open(domain_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Failed to read domain list: {e}{Style.RESET_ALL}")
        return

    domain_queue = queue.Queue()
    for domain in domains:
        domain_queue.put(domain)

    result_list = []
    lock = threading.Lock()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=domain_to_ip_worker, args=(domain_queue, result_list, lock))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    result_dir = "ResultDomainToIP"
    os.makedirs(result_dir, exist_ok=True)
    output_path = os.path.join(result_dir, "DomainToIP.txt")

    with open(output_path, "w") as f:
        for ip in result_list:
            print(ip)
            f.write(ip + "\n")
    print(f"{Fore.LIGHTGREEN_EX}Saved domain-to-IP results to {output_path}{Style.RESET_ALL}")

def main():
    if not SHODAN_API_KEY or SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        print(f"{Fore.RED}Please set your Shodan API key in the SHODAN_API_KEY variable at the top of the script.{Style.RESET_ALL}")
        return

    print(f"{Fore.YELLOW}Choose between (1-3){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1. Grab Domain/Hostname{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}2. Reverse IP to Domain{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}3. Domain to IP{Style.RESET_ALL}")

    while True:
        choice = input(f"{Fore.YELLOW}Enter your choice (1, 2, or 3): {Style.RESET_ALL}").strip()
        if choice == "1":
            grab_domains()
            break
        elif choice == "2":
            reverse_ip_to_domain()
            break
        elif choice == "3":
            domain_to_ip()
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

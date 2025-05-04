import shodan
import threading
import queue
import os
import re
import time
import socket
import random
import sys
import requests
from colorama import init, Fore, Style

try:
    import socks
except ImportError:
    socks = None

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

proxy_list = []
proxy_lock = threading.Lock()

def is_ip(address):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address) is not None

LARAVEL_QUERIES = [
    'http.title:"Whoops! There was an error."',
    'http.html:"Whoops, looks like something went wrong."',
    'http.html:"Laravel Framework"',
    'http.html:"Whoops\\Exception\\ErrorException"',
    'http.html:"Whoops\\Run"',
    'http.html:"laravel.log"',
    'http.html:"laravel"'
]

def get_random_proxy():
    with proxy_lock:
        if not proxy_list:
            return None
        proxy = random.choice(proxy_list)
        if not proxy.startswith("socks5://") and not proxy.startswith("http://") and not proxy.startswith("https://"):
            proxy = "socks5://" + proxy
        return proxy

def remove_bad_proxy(bad_proxy):
    with proxy_lock:
        for i, proxy in enumerate(proxy_list):
            if proxy == bad_proxy or (not proxy.startswith("socks5://") and "socks5://" + proxy == bad_proxy):
                del proxy_list[i]
                break

def setup_proxy_for_request(proxy_url):
    # For requests
    os.environ['HTTP_PROXY'] = proxy_url
    os.environ['HTTPS_PROXY'] = proxy_url
    # For shodan library (uses requests under the hood)
    os.environ['SHODAN_PROXY'] = proxy_url
    # For socket (DNS lookups)
    if socks:
        m = re.match(r'(socks5|http|https)://([\w\.-]+):(\d+)', proxy_url)
        if not m:
            print(f"{Fore.RED}Invalid proxy format. Use socks5://host:port, http://host:port, or https://host:port{Style.RESET_ALL}")
            sys.exit(1)
        proxy_type = m.group(1)
        host = m.group(2)
        port = int(m.group(3))
        if proxy_type == "socks5":
            socks.set_default_proxy(socks.SOCKS5, host, port)
        elif proxy_type == "http":
            socks.set_default_proxy(socks.HTTP, host, port)
        elif proxy_type == "https":
            socks.set_default_proxy(socks.HTTP, host, port)  # HTTPS handled as HTTP for PySocks
        socket.socket = socks.socksocket

def ask_proxy():
    global proxy_list
    use_proxy = input(f"{Fore.YELLOW}With Proxy or No Proxy (1 If Yes, 2 If No): {Style.RESET_ALL}").strip()
    if use_proxy == "1":
        if not socks:
            print(f"{Fore.RED}PySocks is required for proxy support. Install with: pip install pysocks requests[socks]{Style.RESET_ALL}")
            sys.exit(1)
        proxy_file = input(f"{Fore.YELLOW}Enter the path to your Proxy List (e.g, proxy.txt): {Style.RESET_ALL}").strip()
        try:
            with open(proxy_file, "r") as f:
                proxy_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}Failed to read proxy list: {e}{Style.RESET_ALL}")
            sys.exit(1)
        if not proxy_list:
            print(f"{Fore.RED}Proxy list is empty!{Style.RESET_ALL}")
            sys.exit(1)
        print(f"{Fore.LIGHTGREEN_EX}Proxy list loaded with {len(proxy_list)} proxies.{Style.RESET_ALL}")
    else:
        print(f"{Fore.LIGHTGREEN_EX}Proxy not used.{Style.RESET_ALL}")

def shodan_search_worker(api_key, query, page_queue, result_set, lock, total, progress):
    while True:
        try:
            page = page_queue.get_nowait()
        except queue.Empty:
            break
        attempt = 0
        while attempt < 10:
            proxy_url = get_random_proxy()
            if proxy_url:
                setup_proxy_for_request(proxy_url)
            api = shodan.Shodan(api_key)
            try:
                results = api.search(query, page=page)
                with lock:
                    for match in results['matches']:
                        hostnames = match.get('hostnames', [])
                        ip = match.get('ip_str', None)
                        if hostnames:
                            for hostname in hostnames:
                                if not is_ip(hostname):
                                    result_set.add(hostname)
                        elif ip:
                            result_set.add(ip)
                    progress[0] = len(result_set)
                    percent = int((progress[0] / total) * 100)
                    bar = ('#' * (percent // 2)).ljust(50)
                    print(f"\r{Fore.CYAN}Progress: [{bar}] {percent}% ({progress[0]}/{total}){Style.RESET_ALL}", end="")
                break
            except Exception as e:
                if proxy_url:
                    remove_bad_proxy(proxy_url)
                    print(f"{Fore.YELLOW}Proxy failed and removed: {proxy_url} ({e}){Style.RESET_ALL}")
                    if not proxy_list:
                        print(f"{Fore.RED}All proxies are dead. Exiting...{Style.RESET_ALL}")
                        sys.exit(1)
                else:
                    print(f"{Fore.YELLOW}Retrying Shodan page {page} due to error: {e}{Style.RESET_ALL}")
                time.sleep(2)
                attempt += 1
        page_queue.task_done()
        time.sleep(1)  # Respect Shodan's rate limit

def domain_to_ip_worker(domain_queue, result_list, lock):
    while True:
        try:
            domain = domain_queue.get_nowait()
        except queue.Empty:
            break
        for attempt in range(10):
            proxy_url = get_random_proxy()
            if proxy_url:
                setup_proxy_for_request(proxy_url)
            try:
                ip = socket.gethostbyname(domain)
                with lock:
                    result_list.append(ip)
                break
            except Exception as e:
                if proxy_url:
                    remove_bad_proxy(proxy_url)
                    print(f"{Fore.YELLOW}Proxy failed and removed: {proxy_url} ({e}){Style.RESET_ALL}")
                    if not proxy_list:
                        print(f"{Fore.RED}All proxies are dead. Exiting...{Style.RESET_ALL}")
                        sys.exit(1)
                time.sleep(1)

def grab_domains():
    while True:
        try:
            num = int(input(f"{Fore.YELLOW}Enter the number of sites (10-1000000): {Style.RESET_ALL}"))
            if 10 <= num <= 1000000:
                break
            else:
                print(f"{Fore.RED}Please enter a number between 10 and 1000000.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")

    extra_filter = input(f"{Fore.YELLOW}Enter any extra filters (e.g., after:2024-01-01 or just press Enter): {Style.RESET_ALL}").strip()
    try:
        start_page = int(input(f"{Fore.YELLOW}Start from page (default 1): {Style.RESET_ALL}").strip() or "1")
    except ValueError:
        start_page = 1

    country_input = input(f"{Fore.YELLOW}Enter country codes, e.g.: (US,JP,DE) or press Enter to skip: {Style.RESET_ALL}").strip()
   country_list = [c.strip().upper() for c in country_input.split(",") if c.strip()] if country_input else [None]

    print(f"{Fore.YELLOW}Shodan API allows only 1 request per second. Thread count is set to 1 for compliance.{Style.RESET_ALL}")
    num_threads = 1

    for country in country_list:
        print(f"{Fore.LIGHTGREEN_EX}Searching Shodan for Laravel debug pages{f' in {country}' if country else ''} with multiple queries...{Style.RESET_ALL}")

        result_set = set()
        lock = threading.Lock()
        progress = [0]

        for query in LARAVEL_QUERIES:
            full_query = query
            if country:
                full_query += f" country:{country}"
            if extra_filter:
                full_query += " " + extra_filter

            page_queue = queue.Queue()
            pages_needed = (num // 100) + 10
            page_numbers = list(range(start_page, start_page + pages_needed))
            random.shuffle(page_numbers)

            for i in page_numbers:
                page_queue.put(i)

            threads = []
            for _ in range(num_threads):
                t = threading.Thread(target=shodan_search_worker, args=(SHODAN_API_KEY, full_query, page_queue, result_set, lock, num, progress))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

        print()  # Newline after progress bar

        result_dir = f"ResultGrab/{country if country else 'ALL'}"
        os.makedirs(result_dir, exist_ok=True)

        hostnames = []
        ips = []
        for entry in result_set:
            if is_ip(entry):
                ips.append(entry)
            else:
                hostnames.append(entry)

        host_output_path = os.path.join(result_dir, "ResultHost.txt")
        with open(host_output_path, "w") as f:
            for host in hostnames[:num]:
                print(host)
                f.write(host + "\n")

        ip_output_path = os.path.join(result_dir, "ResultIP.txt")
        with open(ip_output_path, "w") as f:
            for ip in ips[:num]:
                print(ip)
                f.write(ip + "\n")

        print(f"{Fore.LIGHTGREEN_EX}Saved {min(len(hostnames), num)} hostnames to {host_output_path}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTGREEN_EX}Saved {min(len(ips), num)} IPs to {ip_output_path}{Style.RESET_ALL}")

def shodan_host_lookup(api, ip, retries=10):
    for attempt in range(retries):
        proxy_url = get_random_proxy()
        if proxy_url:
            setup_proxy_for_request(proxy_url)
        try:
            return api.host(ip)
        except shodan.APIError as e:
            if proxy_url:
                remove_bad_proxy(proxy_url)
                print(f"{Fore.YELLOW}Proxy failed and removed: {proxy_url} ({e}){Style.RESET_ALL}")
                if not proxy_list:
                    print(f"{Fore.RED}All proxies are dead. Exiting...{Style.RESET_ALL}")
                    sys.exit(1)
            if "rate limit" in str(e).lower():
                time.sleep(2)
            else:
                break
        except Exception as e:
            if proxy_url:
                remove_bad_proxy(proxy_url)
                print(f"{Fore.YELLOW}Proxy failed and removed: {proxy_url} ({e}){Style.RESET_ALL}")
                if not proxy_list:
                    print(f"{Fore.RED}All proxies are dead. Exiting...{Style.RESET_ALL}")
                    sys.exit(1)
            time.sleep(2)
    return None

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

    shodan_results = set()
    rdns_results = set()
    lock = threading.Lock()

    api = shodan.Shodan(SHODAN_API_KEY)
    for idx, ip in enumerate(ips, 1):
        result = shodan_host_lookup(api, ip)
        if result:
            hostnames = result.get('hostnames', [])
            with lock:
                for h in hostnames:
                    if h and not is_ip(h):
                        shodan_results.add(h)
            print(f"{Fore.CYAN}[Shodan] {ip}: {hostnames if hostnames else 'No hostnames'} ({idx}/{len(ips)}){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[Shodan] {ip}: No result or error ({idx}/{len(ips)}){Style.RESET_ALL}")
        time.sleep(1)

    def rdns_worker(ip_list):
        for ip in ip_list:
            for attempt in range(10):
                proxy_url = get_random_proxy()
                if proxy_url:
                    setup_proxy_for_request(proxy_url)
                try:
                    rdns = socket.gethostbyaddr(ip)[0]
                    with lock:
                        if rdns and not is_ip(rdns):
                            rdns_results.add(rdns)
                    print(f"{Fore.LIGHTGREEN_EX}[RDNS] {ip}: {rdns}{Style.RESET_ALL}")
                    break
                except Exception as e:
                    if proxy_url:
                        remove_bad_proxy(proxy_url)
                        print(f"{Fore.YELLOW}Proxy failed and removed: {proxy_url} ({e}){Style.RESET_ALL}")
                        if not proxy_list:
                            print(f"{Fore.RED}All proxies are dead. Exiting...{Style.RESET_ALL}")
                            sys.exit(1)
                    if attempt == 9:
                        print(f"{Fore.YELLOW}[RDNS] {ip}: No PTR record or error{Style.RESET_ALL}")

    thread_count = 10
    ip_chunks = [ips[i::thread_count] for i in range(thread_count)]
    threads = []
    for chunk in ip_chunks:
        t = threading.Thread(target=rdns_worker, args=(chunk,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    result_dir = "ResultReverse"
    os.makedirs(result_dir, exist_ok=True)
    output_path = os.path.join(result_dir, "Reverse.txt")

    all_domains = sorted({h for h in (shodan_results | rdns_results) if not is_ip(h)})

    with open(output_path, "w") as f:
        for h in all_domains:
            print(h)
            f.write(h + "\n")
    if all_domains:
        print(f"{Fore.LIGHTGREEN_EX}Saved reverse IP results to {output_path}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No hostnames found for the provided IPs. Output file is empty.{Style.RESET_ALL}")

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

    ask_proxy()

    print(f"{Fore.YELLOW}Choose between (1-3){Style.RESET_ALL}")
    print(ff"{Fore.YELLOW}1. Grab Domain/Hostname{Style.RESET_ALL}")
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

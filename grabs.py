import shodan
import threading
import queue
import os
import re
import time
import socket
import random
import sys
import datetime
from colorama import init, Fore, Style

try:
    import socks
except ImportError:
    socks = None

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"  # <-- Put your Shodan API key here

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
    os.environ['HTTP_PROXY'] = proxy_url
    os.environ['HTTPS_PROXY'] = proxy_url
    os.environ['SHODAN_PROXY'] = proxy_url
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
            socks.set_default_proxy(socks.HTTP, host, port)
        socket.socket = socks.socksocket

def ask_proxy():
    global proxy_list
    use_proxy = input(f"{Fore.YELLOW}With Proxy or No Proxy (1=Yes, 2=No): {Style.RESET_ALL}").strip()
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

def generate_date_ranges(start_date, end_date, delta_days=30):
    ranges = []
    current_start = start_date
    while current_start < end_date:
        current_end = current_start + datetime.timedelta(days=delta_days)
        if current_end > end_date:
            current_end = end_date
        ranges.append((current_start.strftime("%Y-%m-%d"), current_end.strftime("%Y-%m-%d")))
        current_start = current_end + datetime.timedelta(days=1)
    return ranges

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
                    matches = results.get('matches', [])
                    print(f"\n{Fore.MAGENTA}Fetched page {page} with {len(matches)} matches for query: {query}{Style.RESET_ALL}")
                    for match in matches:
                        hostnames = match.get('hostnames', [])
                        ip = match.get('ip_str', None)
                        if hostnames:
                            for hostname in hostnames:
                                if not is_ip(hostname) and hostname not in result_set:
                                    result_set.add(hostname)
                                    print(f"{Fore.GREEN}Found hostname: {hostname}{Style.RESET_ALL}")
                        elif ip and ip not in result_set:
                            result_set.add(ip)
                            print(f"{Fore.GREEN}Found IP: {ip}{Style.RESET_ALL}")
                    progress[0] = len(result_set)
                    percent = int((progress[0] / total) * 100)
                    bar = ('#' * (percent // 2)).ljust(50)
                    print(f"\r{Fore.CYAN}Progress: [{bar}] {percent}% ({progress[0]}/{total}){Style.RESET_ALL}", end="")
                break
            except Exception as e:
                # Suppress retry messages but print on final failure
                attempt += 1
                time.sleep(2)
        page_queue.task_done()
        time.sleep(1)

def grab_domains():
    import math

    while True:
        try:
            total_num = int(input(f"{Fore.YELLOW}Enter the total number of sites to grab (10-1000000): {Style.RESET_ALL}"))
            if 10 <= total_num <= 1000000:
                break
            else:
                print(f"{Fore.RED}Please enter a number between 10 and 1,000,000.{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")

    extra_filter = input(f"{Fore.YELLOW}Enter any extra filters (e.g., country:US) or press Enter to skip: {Style.RESET_ALL}").strip()

    # Define date range for splitting queries (last 3 years)
    end_date = datetime.date.today()
    start_date = end_date - datetime.timedelta(days=365*3)  # 3 years ago

    date_ranges = generate_date_ranges(start_date, end_date, delta_days=30)  # monthly ranges

    country_input = input(f"{Fore.YELLOW}Enter country codes separated by commas (e.g., US,JP,DE) or press Enter to skip: {Style.RESET_ALL}").strip()
    country_list = [c.strip().upper() for c in country_input.split(",") if c.strip()] if country_input else [None]

    print(f"{Fore.YELLOW}Shodan API allows 1 request per second. Thread count set to 1 for compliance.{Style.RESET_ALL}")
    num_threads = 1

    MAX_PAGES = 10  # max pages per query (1000 results)

    result_set = set()
    lock = threading.Lock()
    progress = [0]

    for country in country_list:
        print(f"{Fore.LIGHTGREEN_EX}Starting search for Laravel debug pages{f' in {country}' if country else ''}...{Style.RESET_ALL}")

        for date_start, date_end in date_ranges:
            if len(result_set) >= total_num:
                break  # reached desired total

            for query_base in LARAVEL_QUERIES:
                if len(result_set) >= total_num:
                    break

                # Build query with date range and optional country and extra filters
                query = query_base
                if country:
                    query += f' country:{country}'
                if extra_filter:
                    query += f' {extra_filter}'

                pages_needed = math.ceil((total_num - len(result_set)) / 100)
                pages_needed = min(pages_needed, MAX_PAGES)

                page_numbers = list(range(1, pages_needed + 1))

                print(f"{Fore.CYAN}DEBUG: Query: {query}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}DEBUG: Pages to query: {page_numbers}{Style.RESET_ALL}")

                page_queue = queue.Queue()
                for p in page_numbers:
                    page_queue.put(p)

                threads =                threads = []
                for _ in range(num_threads):
                    t = threading.Thread(target=shodan_search_worker, args=(SHODAN_API_KEY, query, page_queue, result_set, lock, total_num, progress))
                    t.start()
                    threads.append(t)

                for t in threads:
                    t.join()

                if len(result_set) >= total_num:
                    break

        print(f"\n{Fore.LIGHTGREEN_EX}Search complete for {country if country else 'ALL'}. Total results collected: {len(result_set)}{Style.RESET_ALL}")

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
            for host in hostnames[:total_num]:
                print(host)
                f.write(host + "\n")

        ip_output_path = os.path.join(result_dir, "ResultIP.txt")
        with open(ip_output_path, "w") as f:
            for ip in ips[:total_num]:
                print(ip)
                f.write(ip + "\n")

        print(f"{Fore.LIGHTGREEN_EX}Saved {min(len(hostnames), total_num)} hostnames to {host_output_path}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTGREEN_EX}Saved {min(len(ips), total_num)} IPs to {ip_output_path}{Style.RESET_ALL}")

def main():
    ask_proxy()
    while True:
        print(f"{Fore.YELLOW}Choose between (1-3){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}1. Grab Domain/Hostname{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}2. Reverse IP to Domain (Not implemented){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}3. Domain to IP (Not implemented){Style.RESET_ALL}")
        choice = input(f"{Fore.YELLOW}{Style.BRIGHT}Enter your choice (1, 2, or 3): {Style.RESET_ALL}")
        if choice == "1":
            grab_domains()
        elif choice == "2":
            print(f"{Fore.RED}Reverse IP to Domain not implemented.{Style.RESET_ALL}")
        elif choice == "3":
            print(f"{Fore.RED}Domain to IP not implemented.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

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

SHODAN_API_KEY = "YOUR_SHODAN_APIKEY"  # <-- Put your Shodan API key here

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
    'http.html:"laravel"',
    'http.html:"laravel_session"',
    'http.html:"APP_KEY"',
    'http.html:"APP_ENV"',
    'http.html:"DB_HOST"',
    'http.html:"DB_DATABASE"',
    'http.html:"DB_USERNAME"',
    'http.html:"DB_PASSWORD"',
    'http.html:"APP_DEBUG"',
    'http.html:"APP_URL"',
    'http.html:"APP_NAME"',
    'http.html:"APP_ENV=production"',
    'http.html:"APP_ENV=local"',
    'http.html:"APP_ENV=development"',
    'http.html:"APP_ENV=staging"',
    'http.html:"APP_ENV=testing"',
    'http.html:"laravel.log" port:80',
    'http.html:"laravel.log" port:443',
    'http.html:"laravel.log" port:8080',
    'http.html:"laravel.log" port:8000',
    'http.html:"laravel.log" port:8888',
    'http.html:"laravel.log" port:8443',
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

def shodan_search_worker(api_key, query, page_queue, result_set, lock, total, progress, host_output_path, ip_output_path):
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
                                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    print(f"{Fore.GREEN}Found hostname: {hostname}{Style.RESET_ALL}")
                                    with open(host_output_path, "a") as f:
                                        f.write(hostname + "\n")
                        elif ip and ip not in result_set:
                            result_set.add(ip)
                            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"{Fore.GREEN}Found IP: {ip}{Style.RESET_ALL}")
                            with open(ip_output_path, "a") as f:
                                f.write(ip + "\n")
                    progress[0] = len(result_set)
                    percent = int((progress[0] / total) * 100)
                    bar = ('#' * (percent // 2)).ljust(50)
                    print(f"\r{Fore.CYAN}Progress: [{bar}] {percent}% ({progress[0]}/{total}){Style.RESET_ALL}", end="")
                break
            except Exception as e:
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

    extra_filter = input(f"{Fore.YELLOW}Enter any extra filters (e.g., hostname:.id) or press Enter to skip: {Style.RESET_ALL}").strip()

    # Define date range for splitting queries (last 3 years)
    end_date = datetime.date.today()
    start_date = end_date - datetime.timedelta(days=365*3)  # 3 years ago

    date_ranges = generate_date_ranges(start_date, end_date, delta_days=30)  # monthly ranges

    country_input = input(f"{Fore.YELLOW}Enter country codes separated by commas (e.g., US,JP,DE) or press Enter to skip: {Style.RESET_ALL}").strip()
    country_list = [c.strip().upper() for c in country_input.split(",") if c.strip()] if country_input else []

    print(f"{Fore.YELLOW}Shodan API allows 1 request per second. Thread count set to 1 for compliance.{Style.RESET_ALL}")
    num_threads = 1

    MAX_PAGES = 10  # max pages per query (1000 results)

    # If no countries are specified, treat it as a global search (no country filter)
    if not country_list:
        country_list = [None]
        per_country_quota = total_num
    else:
        # Split the quota among countries
        per_country_quota = total_num // len(country_list)
        remainder = total_num % len(country_list)

    try:
        for idx, country in enumerate(country_list):
            this_country_quota = per_country_quota + (1 if idx < remainder else 0) if country_list != [None] else per_country_quota
            if this_country_quota == 0:
                continue

            print(f"{Fore.LIGHTGREEN_EX}Starting search for Laravel debug pages in {country if country else 'ALL'} (quota: {this_country_quota})...{Style.RESET_ALL}")

            result_dir = f"ResultGrab/{country if country else 'ALL'}"
            os.makedirs(result_dir, exist_ok=True)
            now_str = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            host_output_path = os.path.join(result_dir, f"ResultHost_{now_str}.txt")
            ip_output_path = os.path.join(result_dir, f"ResultIP_{now_str}.txt")


            open(host_output_path, "w").close()
            open(ip_output_path, "w").close()

            result_set = set()
            lock = threading.Lock()
            progress = [0]

            for date_start, date_end in date_ranges:
                if len(result_set) >= this_country_quota:
                    break

                for query_base in LARAVEL_QUERIES:
                    if len(result_set) >= this_country_quota:
                        break

                    query = query_base
                    if country:
                        query += f' country:{country}'
                    if extra_filter:
                        query += f' {extra_filter}'

                    pages_needed = min(math.ceil((this_country_quota - len(result_set)) / 100), MAX_PAGES)
                    page_numbers = list(range(1, pages_needed + 1))

                    print(f"{Fore.CYAN}DEBUG: Query: {query}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}DEBUG: Pages to query: {page_numbers}{Style.RESET_ALL}")

                    page_queue = queue.Queue()
                    for p in page_numbers:
                        page_queue.put(p)

                    threads = []
                    for _ in range(num_threads):
                        t = threading.Thread(
                            target=shodan_search_worker,
                            args=(
                                SHODAN_API_KEY, query, page_queue, result_set, lock,
                                this_country_quota, progress, host_output_path, ip_output_path
                            )
                        )
                        t.start()
                        threads.append(t)

                    for t in threads:
                        t.join()

                    if len(result_set) >= this_country_quota:
                        break

            print(f"\n{Fore.LIGHTGREEN_EX}Search complete for {country if country else 'ALL'}. Total results collected: {len(result_set)}{Style.RESET_ALL}")
            print(f"{Fore.LIGHTGREEN_EX}Saved hostnames to {host_output_path}{Style.RESET_ALL}")
            print(f"{Fore.LIGHTGREEN_EX}Saved IPs to {ip_output_path}{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user! Exiting...{Style.RESET_ALL}")
        sys.exit(0)

def domain_to_ip():
    filename = input(f"{Fore.YELLOW}Enter the filename containing domains (one per line): {Style.RESET_ALL}").strip()
    result_dir = "ResultDomainToIP"
    os.makedirs(result_dir, exist_ok=True)
    now_str = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = os.path.join(result_dir, f"DomainToIP_{now_str}.txt")

    if not os.path.isfile(filename):
        print(f"{Fore.RED}File not found: {filename}{Style.RESET_ALL}")
        return
    with open(filename, "r") as f, open(output_file, "w") as out:
        for line in f:
            domain = line.strip()
            if not domain:
                continue
            try:
                ip = socket.gethostbyname(domain)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"{Fore.GREEN}{domain} -> {ip}{Style.RESET_ALL}")
                out.write(f"{ip}\n")
            except Exception as e:
                print(f"{Fore.RED}Failed to resolve {domain}: {e}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}Results saved to {output_file}{Style.RESET_ALL}")

def reverse_ip_to_domain():
    filename = input(f"{Fore.YELLOW}Enter the filename containing IPs (one per line): {Style.RESET_ALL}").strip()
    result_dir = "ResultReverse"
    os.makedirs(result_dir, exist_ok=True)
    now_str = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = os.path.join(result_dir, f"Resultreverse_{now_str}.txt")
    api = shodan.Shodan(SHODAN_API_KEY)
    if not os.path.isfile(filename):
        print(f"{Fore.RED}File not found: {filename}{Style.RESET_ALL}")
        return
    with open(filename, "r") as f, open(output_file, "w") as out:
        for line in f:
            ip = line.strip()
            if not ip:
                continue
            try:
                host_info = api.host(ip)
                hostnames = set(host_info.get("hostnames", []))
                domains = set(host_info.get("domains", []))
                all_domains = hostnames | domains
                if all_domains:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"{Fore.GREEN}{ip} -> {len(all_domains)} domains/hostnames found{Style.RESET_ALL}")
                    for d in all_domains:
                        out.write(f"{d}\n")
                else:
                    print(f"{Fore.YELLOW}{ip} -> No domains/hostnames found{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Shodan error for {ip}: {e}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX}Results saved to {output_file}{Style.RESET_ALL}")

def main():
    ask_proxy()
    while True:
        print(f"{Fore.YELLOW}Choose between (1-3){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}1. Grab Domain/Hostname{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}2. Reverse IP to Domain{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}3. Domain to IP{Style.RESET_ALL}")
        choice = input(f"{Fore.YELLOW}{Style.BRIGHT}Enter your choice (1, 2, or 3): {Style.RESET_ALL}")
        if choice == "1":
            grab_domains()
        elif choice == "2":
            reverse_ip_to_domain()
        elif choice == "3":
            domain_to_ip()
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

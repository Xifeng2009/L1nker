#!/usr/bin/python3
USAGE = '''Example:
l1nker.py -u https://target.com
l1nker.py -u https://target.com -o result.txt
l1nker.py -u https://target.com -ins api.target.com,target.com
l1nker.py -u https://target.com -oos blog.target.com,peoc.target.com,translator.target.com
l1nker.py -u https://target.com --headers 'User-Agent: ______\nReferer: ______' --cookies 'Session: _______'
'''
import requests, re, argparse, time, os, sys, platform, wfuzz, subprocess, json, queue, urllib3
from bs4 import BeautifulSoup
from threading import Thread, Lock, Semaphore

GET, POST, SCRIPT, TRAP, TRASH, EPT = 'GET', 'POST', 'SCRIPT', 'TRAP', 'TRASH', 'EPT'

def parser():
    parser = argparse.ArgumentParser(prog='L1nker', conflict_handler='resolve')
    parser.add_argument('-u', '--url', required=True, type=str, help='REQUEST URL')
    parser.add_argument('--headers', type=str, default='', help='REQUEST HEADER (e.g. User-Agent: _______\nReferer: ________')
    parser.add_argument('--cookies', type=str, default='', help='REQUEST COOKIE')
    parser.add_argument('-p', '--proxy', type=str, help='PROXY SERVER (e.g. http://127.0.0.1:8080')
    parser.add_argument('-oos', '--out-of-scope', type=str, default='', help='DOMAIN WITH NO MONEY (e.g. blog.target.com,x.target.com')
    parser.add_argument('-ins', '--in-scope', type=str, default='', help='DOMAIN ONLY WITH MONEY')
    # parser.add_argument('-v', '--verbose', action='store_true', help='VERBOSE')
    parser.add_argument('--timeout', default=1, type=int, help='TIMEOUT')
    parser.add_argument('-t', '--threads', default=10, type=int, help='THREADS')
    parser.add_argument('-o', '--output', type=str, help='output_file FILE')
    parser.add_argument('--debug', action='store_true', help='DEBUG MODE')
    parser.add_argument('-h', '--help', action='store_true', help='PRINT THIS')
    return parser

class L1nker:
    def __init__(self, url, headers={}, cookies={}):
        self.url = url
        self.headers = {i.replace(' ','').split(':')[0]:i.split(':')[1] for i in headers.split('\n')} if headers else {}
        self.cookies = {i.replace(' ','').split('=')[0]:i.split('=')[1] for i in cookies.split('; ')} if cookies else {}

    @staticmethod
    def get_domain(url):
        return re.sub(r'www\.', '', re.match(r'https?:\/\/(?P<domain>[a-zA-Z0-9.-]*)\/?', url).group('domain'))

    @staticmethod
    def print_ok(msg=''):
        for i in range(3):
            time.sleep(0.033)
            print('.', end='')
        print("OK" if not msg else msg)

    @staticmethod
    def output(fp, data):
        with open(fp, 'a') as f:
            f.write(data + '\n')

    def analyze_url(self):
        print("[*] Analyzing URL", end='')
        self.base_url = url.rstrip('/')
        self.protocol = 'http' if url.startswith('http://') else 'https'
        '''
        www.google.co.uk
        www.google.com
        google.com
        localhost
        127.0.0.1
        '''
        _domain = re.match(r'https?://(?P<domain>[a-z0-9-.]*)/?', self.base_url).group('domain').rstrip('/')
        self.domain = _domain if _domain.count('.') in [0, 1] else '.'.join(_domain.split('.')[1:])
        self.subdomain = self.get_domain(self.base_url)
        self.print_ok()

    def config(self):
        print("[*] Configuring Detact", end='')
        self.is_win32 = True if platform.system() == 'Windows' else False
        self.session_fp = os.path.join(os.getcwd(), '.local', 'share', 'l1nker', 'output', self.domain)
        self.scope = {self.subdomain: []}
        self.q = queue.Queue()
        self.q.put(self.url)
        self.print_ok()

    def build_threading(self):
        print("[*] Building Threading", end='')
        self.lock = Lock()
        self.sema = Semaphore(threads)
        self.print_ok()

    def build_session(self):
        print("[*] Building Request", end='')
        self.s = requests.Session()
        a = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=200)
        self.s.mount(f"{self.protocol}://*.{self.domain}", a)
        self.s.headers.update(self.headers)
        self.s.cookies.update(self.cookies)
        self.s.proxies.update(proxies)
        self.print_ok()

    def load_session(self):
        # /root/.local/share/sqlmap/output/ac141f8f1f945195c0b90f340096003e.web-security-academy.net
        fp = os.path.join(self.session_fp, 'session.json')
        if os.path.exists(fp) and input("[*] Read Session From Storage? (y/N) ").upper() == 'Y':
            fp = open(fp, 'r')
            self.scope.update(json.load(fp))

    def save_session(self):
        print("[*] Saving Session...", end='')
        if not os.path.exists(self.session_fp):
            os.makedirs(self.session_fp)
        fp = open(os.path.join(self.session_fp, 'session.json'), 'w')
        json.dump(self.scope, fp)
        self.print_ok()

    @staticmethod
    def find_ept_by_linkfinder(domain, url, link):
        file_path = r"C:\Users\WhoAmI\Desktop\Tools\LinkFinder\linkfinder.py"
        cmd = f"python3 {file_path} -i {link} -o cli" if platform.system() == 'Windows' else f"linkfinder -i {link} -o cli"
        encoding = 'GB2312' if platform.system() == 'Windows' else 'UTF-8'
        env = dict(os.environ)
        env['http_proxy'] = proxy['http']
        env['https_proxy'] = proxy['http']
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, env=env)
        lst = []
        for line in iter(p.stdout.readline, b''):
            line = line.strip().decode(encoding)
            # print(f"[?] {line}")
            lst.append(line)
        return lst

    def extract_link_from_html(self, html):
        lst = []
        soup = BeautifulSoup(html, 'lxml')
        for item in soup.find_all('a'):  # href
            link = item.get('href')
            if link:
                lst.append((GET, link))
        for item in soup.find_all('form'):  # form action
            link = item.get('action')
            if link:
                lst.append((POST, link))
        for item in soup.find_all('script'):  # js
            link = item.get('src')
            if link:
                lst.append((SCRIPT, link))
        return lst

    def filter_clean_links(self, domain, url, links):
        if debug: print("[!] Filter: Clean Links")
        for typE, link in links:
            if re.match(r'.*\.(json|7z|a|apk|ar|bz2|cab|cpio|deb|dmg|egg|gz|iso|jar|lha|mar|pea|rar|rpm|s7z|shar|tar|tbz2|tgz|tlz|war|whl|xpi|zip|zipx|xz|pak|aac|aiff|ape|au|flac|gsm|it|m3u|m4a|mid|mod|mp3|mpa|pls|ra|s3m|sid|wav|wma|xm|3dm|3ds|max|bmp|dds|gif|jpg|jpeg|png|psd|xcf|tga|thm|tif|tiff|yuv|ai|eps|ps|svg|dwg|dxf|gpx|kml|kmz|webp|3g2|3gp|aaf|asf|avchd|avi|drc|flv|m2v|m4p|m4v|mkv|mng|mov|mp2|mp4|mpe|mpeg|mpg|mpv|mxf|nsv|ogg|ogv|ogm|qt|rm|rmvb|roq|srt|svi|vob|webm|wmv|yuv|css)$', link):
                continue
            if re.search(r'\s', link):
                continue
            if re.match(r'\/\/', link):
                yield typE, f"{self.protocol}:{link}"
            elif re.match(r'\/', link):
                yield typE, f"{self.protocol}://{domain}{link}"
            elif re.match(r'https?:\/\/([a-zA-Z0-9-]+\.)*{}'.format(domain), link):
                yield typE, link
            elif re.match(r'\w+', link) and not re.match(r'https?:\/\/', link) and not re.match(r'mailto:', link):  # page
                yield typE, f"{url}/{link}"
            elif re.match(r'https?:\/\/.*\/.*\.js', link):
                yield typE, link
            if not re.match(r'https?:\/\/[a-zA-Z0-9-.]*{}'.format(self.domain), link) and not re.match(r'.*\.js$', link):  # ilegal domain
                continue
            if re.match(r'[@#]', link) or re.match(r'javascript:', link, re.I):  # @# | javascript:
                continue

    def filter_bypass_trap(self, links):
        if debug: print("[!] Filter: Bypass Trap")
        lst = []
        for typE, link in links:
            if re.search(r'\/(logout|log_out|deactivate|exit|quit)', link):
                lst.append((TRAP, link))
            elif re.search(r'\/(fr|es|ja|en-GB|zh|cn)(\/|$)', link, re.I):  # todo://add more lang
                # lst.append((TRASH, link))
                continue
            else:
                lst.append((typE, link))
        return lst

    def filter_duplicates(self, domain, url, links):
        if debug: print("[!] Filter: Remove Duplicates")
        lst = []
        for typE, link in links:
            link = re.sub(r':\/\/www\.', '://', link)  # Remove www.
            lin_ = re.sub(r'#.*', '', re.sub(r'\?.*', '', link))  # Remove parameters
            if self.scope.get(domain):
                if lin_ not in self.scope.get(domain):
                    self.scope[domain].append(lin_)
                    lst.append((typE, link))
            else:
                if ins:
                    if domain in ins:
                        self.scope[domain] = [lin_]
                        lst.append((typE, link))
                else:
                    if domain not in oos:  # out of scope
                        self.scope[domain] = [lin_]
                        lst.append((typE, link))
        return lst

    def request(self, url):
        try:
            return self.s.get(url, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"[!] RequestException: {e}") if debug else print(end='')

    def crawl(self, url):
        self.sema.acquire()
        r = self.request(url)
        try:
            html, status = r.text, r.status_code
        except Exception as e:
            print(e)
            return
        domain = self.get_domain(url)
        links  = self.extract_link_from_html(html)
        links  = self.filter_clean_links(domain, url, links)
        links  = self.filter_bypass_trap(links)
        links  = self.filter_duplicates(domain, url, links)
        for typE, link in links:
            if typE == GET:
                if re.search(r'\?', link):
                    print(f"[+] [EPT] {link}")
                    if output_file: self.output(output_file, link)
                self.q.put(link)
            elif type == SCRIPT:
                print(f"[+] [SCRIPT] {link}")
                # links2 = self.find_ept_by_linkfinder(domain, url, link)
                # links2 = self.filter_clean_links(domain, url, links2)
                # links2 = self.filter_bypass_trap(links2)
                # links2 = self.filter_duplicates(domain, url, links2)
                # for link2 in links2:
                #     print(f"[?] {links2}")
            elif typE == POST:
                print(f"[+] [POST] {link} <----- [{url}]")  # todo:// auto test
            elif typE == TRAP:
                print(f"[-] [TRAP] {link}")
            elif typE == TRASH:
                print(f"[-] [TRASH] {link}")
        self.sema.release()

    def start(self):
        self.analyze_url()
        self.config()
        self.build_threading()
        self.build_session()
        # self.load_session()
        while not self.q.empty():
            ts = []
            for i in range(self.q.qsize()):
                t = Thread(target=self.crawl, args=(self.q.get(),))
                t.daemon = True
                ts.append(t)
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        # self.save_session()

ap = parser()
args = ap.parse_args()
if args.help:
    print(USAGE)
    ap.print_help()
    sys.exit(0)

url          = args.url
timeout      = args.timeout
output_file  = args.output
threads      = args.threads
oos          = args.out_of_scope.replace(' ', '').split(',') if args.out_of_scope else []
ins          = args.in_scope.replace(' ', '').split(',') if args.in_scope else []
print(f"[!] Out of Scope: {', '.join(oos)}") if oos else print(end='')
print(f"[!] In Scope:     {', '.join(ins)}") if ins else print(end='')
proxy_ip     = re.match(r'https?:\/\/(?P<ip>[0-9.]*):', args.proxy).group('ip') if args.proxy else ''
proxy_port   = re.match(r'https?:\/\/[a-zA-Z0-9-.]*:(?P<port>\d+)\/?', args.proxy).group('port') if args.proxy else ''
proxy_type   = 'HTTP'
proxies      = {'http': args.proxy, 'https': args.proxy}
fake_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.147 Safari/537.36',
    'Referer': 'https://google.com.jp'
}
debug        = args.debug

L1nker(url, headers=args.headers, cookies=args.cookies).start()
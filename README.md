# eXSS Scanner GUI

eXSS is a simple Cross-Site Scripting (XSS) vulnerability scanner with a graphical user interface (GUI). It helps you find potential XSS vulnerabilities on websites by crawling pages, identifying input points (like URL parameters and forms), and testing them with various XSS payloads.

**Disclaimer:** This tool is for educational and ethical testing purposes only. Always obtain explicit permission before scanning any website or system. Unauthorized scanning can be illegal.

## Features

*   **GUI Interface:** Easy-to-use graphical interface built with Tkinter.
*   **Scan Types:**
    *   **Crawl and Scan:** Start from a URL, crawl the website to find more pages and input forms, and then scan all discovered injection points.
    *   **Scan Single URL (GET/POST):** Scan only the parameters found in the query string of a single URL and forms on that page.
    *   **Scan Single URL (DOM):** Use a headless browser (Selenium) to test for DOM-based XSS on a specific page and a target HTML element.
*   **Injection Point Discovery:** Automatically identifies URL parameters (GET) and form fields (GET/POST) during crawling or single-URL scans.
*   **Payloads:**
    *   Includes a built-in list of common XSS payloads.
    *   Allows loading custom payloads from a text file.
*   **Headers and Cookies:** Option to include custom HTTP headers and cookies in scan requests.
*   **Multi-threading:** Uses threading to speed up the scanning process (for GET/POST scans).
*   **Timeout:** Configure a timeout for requests to avoid hanging on slow responses.
*   **Results:** Displays potential vulnerabilities in a results area.
*   **Report Saving:** Save findings to a text report file.
*   **Stop Scan:** Allows you to stop a running scan gracefully.

## Requirements

Before you can run the scanner, you need to have Python installed on your computer, along with several Python libraries.

1.  **Python 3:** Download and install the latest version of Python 3 from [python.org](https://www.python.org/). Make sure to check the box that says "Add Python to PATH" during installation (especially on Windows).
2.  **Required Python Libraries:** Open your terminal or command prompt and run the following command to install the necessary libraries:
    ```bash
    pip install requests beautifulsoup4 selenium
    ```
3.  **WebDriver (for DOM scanning):** The DOM scanning feature requires a web browser driver. Google Chrome and ChromeDriver are commonly used.
    *   **Install Google Chrome:** If you don't have it, download and install Google Chrome from [google.com/chrome/](https://www.google.com/chrome/).
    *   **Download ChromeDriver:** You need a version of ChromeDriver that matches your Chrome browser version.
        *   Check your Chrome version by going to `chrome://version/` in your Chrome browser.
        *   Go to the [ChromeDriver Downloads page](https://chromedriver.chromium.org/downloads).
        *   Find the ChromeDriver version that corresponds to your Chrome version.
        *   Download the appropriate zip file for your operating system.
        *   Extract the zip file. You will find an executable file named `chromedriver` (or `chromedriver.exe` on Windows).
        *   **Option A (Recommended):** Place the `chromedriver` executable in a directory that is included in your system's PATH. This allows Python to find it automatically.
        *   **Option B (Manual Path):** If you can't or don't want to add it to your PATH, you'll need to set the `CHROME_DRIVER_PATH` variable in the Python script to the full path of the `chromedriver` executable.

## How to Run

1.  Save the Python code into a file named `eXSS.py` (or any `.py` extension).
2.  Open your terminal or command prompt.
3.  Navigate to the directory where you saved the file.
4.  Run the script using the command:
    ```bash
    python eXSS.py
    ```
5.  The GUI window should appear.

## How to Use

1.  **Target URL:** Enter the full URL of the website or page you want to scan (e.g., `https://example.com/`).
2.  **Scan Type:** Select the type of scan you want to perform:
    *   `Crawl and Scan`: Starts crawling from the Target URL.
    *   `Scan Single URL (GET/POST)`: Only scans the parameters of the Target URL and forms found on that specific page.
    *   `Scan Single URL (DOM)`: Scans the Target URL specifically for DOM XSS by interacting with an element. Requires you to specify the `DOM Element Selector`.
3.  **DOM Element Selector (for DOM Scan):** If you chose "Scan Single URL (DOM)", enter the CSS selector for the HTML element you want to test (e.g., `#search-input`, `.comment-box`, `input[name="user_data"]`).
4.  **Timeout (s):** Set the maximum time in seconds to wait for a response from the server or for browser actions.
5.  **Threads (for GET/POST scans):** Set the number of threads to use for concurrent scanning. More threads can be faster but may put more load on the target server.
6.  **Load Payloads from File:** (Optional) Click this button to select a text file containing additional XSS payloads (one payload per line). If you don't load a file, the scanner will use its built-in default payloads. The label will show how many payloads are loaded.
7.  **Headers and Cookies:** (Optional) Enter custom HTTP headers (like `Cookie: sessionid=abc123`) and cookies (like `mycookie=myvalue`) if needed for authenticated or specific testing. Enter one header/cookie per line in the format `Key: Value` or `key=value`.
8.  **Start Scan:** Click this button to begin the scan.
9.  **Stop Scan:** Click this button to stop a running scan.
10. **Scan Results:** The text area will show the progress and any potential XSS vulnerabilities found.
11. **Save Report:** After the scan finishes (or is stopped), if any vulnerabilities were found, this button will become active. Click it to save the findings to a text file.

## Understanding the Results

The "Scan Results" area will display messages indicating the scanner's activity (crawling URLs, testing parameters, etc.).

If a potential vulnerability is found, you will see a line similar to this:
  [VULNERABLE] Potential XSS found: Payload '<script>alert('XSS')</script>' reflected in response for parameter 'search'
  
This tells you:

*   `[VULNERABLE]`: The scanner suspects an XSS vulnerability.
*   `Potential XSS found`: A possible finding.
*   `Payload '...' reflected`: The specific payload that was used.
*   `in response for parameter '...'`: Where the payload was found to be reflected (the parameter name).
*   Details about the injection point type (URL Parameter, Form, DOM), method (GET, POST, DOM), and the URL tested will also be logged above this line.

**Note:** This is an automated scanner. It may produce false positives (reporting a vulnerability where none exists) or miss some vulnerabilities. Always manually verify any findings.

Suggestions for contributions include:

*   Adding more advanced XSS payloads.
*   Implementing different detection methods (e.g., checking for specific JavaScript execution).
*   Improving the crawling logic (e.g., handling JavaScript links).
*   Adding support for other injection points (headers, cookies, JSON).
*   Enhancing the UI or reporting features.



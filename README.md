# oXSS - Advanced GUI-Based XSS Scanner

![GitHub License](https://img.shields.io/github/license/TheOSuite/oXSS)
![Python Version](https://img.shields.io/badge/python-3.13-blue)
![Last Updated](https://img.shields.io/date/2025-07-21)

Welcome to **oXSS**, an open-source, feature-rich GUI-based tool for detecting Cross-Site Scripting (XSS) vulnerabilities in web applications. Built with Python, Tkinter, Selenium, and multithreading, oXSS provides an intuitive interface for security researchers and penetration testers to scan websites for reflected, DOM, and stored XSS vulnerabilities. This tool is designed for educational purposes and must only be used on systems with explicit permission.

## Features

- **GUI Interface**: User-friendly Tkinter-based interface for configuring and monitoring scans.
- **Multiple Scan Types**: Supports Crawl and Scan, Single URL (GET/POST), DOM, and Stored XSS scanning.
- **Advanced Crawling**: Utilizes a priority-based crawler with sitemap parsing, event-driven JS interactions, and API endpoint discovery.
- **WAF Detection**: Identifies common Web Application Firewalls (e.g., Cloudflare, AWS WAF) with bypass payload support.
- **Multithreading**: Leverages multiple threads for efficient scanning of large sites.
- **Payload Management**: Load custom payloads from files and use contextual payload sets.
- **Authentication Support**: Handles login forms for authenticated scans.
- **Reporting**: Export results in TXT, HTML, or JSON formats.
- **State Management**: Pause, resume, and save scan states for later continuation.
- **Stealth Features**: Random user-agent rotation and configurable delays to avoid detection.

## Installation

### Prerequisites
- Python 3.13 or higher
- Ensure the following dependencies are installed:
  - `requests`
  - `beautifulsoup4`
  - `selenium`
  - `webdriver-manager`
  - `lxml`

### Steps
1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/oXSS.git
   cd oXSS
   ```

2. **Install Dependencies**
   Create a virtual environment (optional but recommended) and install required packages:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run the Script**
   Launch the GUI:
   ```bash
   python oXSS.py
   ```

   **Note**: Ensure Chrome browser is installed, as `webdriver-manager` will automatically download the matching ChromeDriver.

## Usage

1. **Configure Scan**
   - Enter the target URL in the "Target URL" field.
   - Select the scan type (e.g., Crawl and Scan, DOM Scan).
   - For DOM scans, specify the CSS selector of the input element.
   - Adjust timeout, threads, max depth, proxy, and blacklist as needed.
   - Load payloads from a `.txt` file or use defaults.
   - Add headers, cookies, or authentication details if required.

2. **Start Scan**
   - Click "Start Scan" to begin. Monitor progress in the "Scan Results" window.
   - Use "Pause Scan" or "Stop Scan" to control the process.
   - Resume paused scans with "Resume Scan".

3. **View Results**
   - Vulnerabilities are displayed in real-time with details (URL, payload, etc.).
   - Save reports using "Save Report" in TXT, HTML, or JSON format.

4. **Profiles**
   - Save or load scan configurations using the "Save Profile" and "Load Profile" buttons.

## Known Issues and Workarounds

- **GPU Errors**: Logs may show `Failed to create GLES3 context` errors due to headless mode on some systems. This is a known Selenium/ChromeDriver issue and does not affect functionality. To minimize, ensure `--disable-gpu` and `--disable-software-rasterizer` are included (already implemented).
- **Selenium Instability**: If the WebDriver crashes, the script attempts to reinitialize it. Ensure no stale `chromedriver.exe` processes are running (check Task Manager and terminate if needed).
- **Performance**: Large sites may be slow due to Selenium overhead. Consider reducing thread count or using a proxy for faster requests.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/awesome-feature`).
3. Commit your changes (`git commit -m "Add awesome feature"`).
4. Push to the branch (`git push origin feature/awesome-feature`).
5. Open a Pull Request.

### Guidelines
- Follow PEP 8 style guidelines.
- Add tests or documentation for new features.
- Address any feedback from maintainers.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by modern DAST tools like Burp Suite and Invicti.
- Built with open-source libraries: Tkinter, Selenium, BeautifulSoup, etc.
- Thanks to the security community for insights into XSS detection techniques.

## Future Enhancements

- **AI-Powered Payloads**: Integrate machine learning for dynamic payload generation.
- **Real-Time Charts**: Add progress visualization (e.g., URLs crawled, vulns found).
- **Proxy Rotation**: Support rotating proxies for better stealth.
- **Blind XSS**: Implement out-of-band detection with a callback server.

For issues or suggestions, please open an issue on the [GitHub Issues page](https://github.com/TheOSuite/oXSS/issues).

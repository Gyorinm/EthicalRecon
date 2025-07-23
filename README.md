# EthicalRecon
EthicalRecon is an open-source comprehensive information gathering tool designed for educational and ethical penetration testing purposes. It helps security researchers collect detailed data about domains, including DNS records, WHOIS information, open ports, website directories, and technologies used. Use responsibly and with permission.

## Why Choose EthicalRecon?

EthicalRecon stands out among similar tools due to its comprehensive all-in-one approach to domain reconnaissance. Unlike tools that specialize in a single aspect, EthicalRecon combines WHOIS lookup, DNS enumeration, port scanning, directory discovery, and technology detection into one easy-to-use Python tool. It generates detailed JSON reports for both manual review and automation, making it ideal for security researchers and ethical hackers who want thorough insights with minimal setup. Its educational focus encourages responsible use, and its modular design allows for easy expansion and customization.

how to use 
--------------------
# Basic scan on example.com
python html.py -t example.com
# → Performs a default scan on the target domain.

# Scan example.com and export the result as JSON
python html.py -t example.com -o json
# → Scans the domain and saves output in JSON format (useful for APIs or automation).

# Scan example.com and export result as HTML into report.html
python html.py -t example.com -o html -f report.html
# → Exports the scan result into a well-formatted HTML report named "report.html".

# Scan example.com with verbose output
python html.py -t example.com -v
# → Displays detailed scan information in the terminal (for debugging or more insights).


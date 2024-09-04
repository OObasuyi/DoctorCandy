from fpdf import FPDF

# Create a PDF class
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'List of URLs and IP Addresses', 0, 1, 'C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

# List of URLs and IP Addresses
url_list = [
    "192.168.1.1",
    "example.com",
    "sub.example.com",
    "10.0.0.1",
    "resource[.]example.com",
    "www.google.com",
    "172.16.0.254",
    "api.twitter.com",
    "203.0.113.0",
    "192.0.2.0",
    "resource[.]subdomain.example.com",
    "subdomain[.]example.com",
    "8.8.8.8",
    "example.net",
    "subdomain.example.net",
    "www.microsoft.com",
    "example.org",
    "resource[.]example.net",
    "api.example.org",
    "203.0.113.255",
    "mail.example.com",
    "192.0.2.255",
    "resource[.]example.org",
    "10.0.0.254",
    "ftp.example.com",
    "subdomain[.]example.org",
    "198.51.100.1",
    "webmail.example.com",
    "localhost",
    "example.edu",
    "resource[.]example.edu",
    "dev.example.com",
    "172.16.255.254",
    "subdomain.example.edu",
    "docs.google.com",
    "support.example.com",
    "198.51.100.255",
    "vpn.example.com",
    "www.example.com",
    "resource[.]example[.]com",
    "192.168.0.1",
    "subdomain.example.org",
    "resource[.]example.edu",
    "api.example.net",
    "example.co.uk",
    "subdomain[.]example[.]com",
    "10.1.1.1",
    "shop.example.com",
    "192.168.100.100",
    "resource[.]example[.]co.uk",
    "hyphen-site.com",
    "sub-domain.example.com",
    "test-site[.]example.com",
    "example-site.org",
    "hyphen-example.net",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "2001:0db8:0000:0042:0000:8a2e:0370:7334",
    "subdomain-hyphen.example.com",
    "example-hyphen[.]net",
    "resource[.]sub-domain[.]example.com",
    "ipv6test[.]example[.]com",
    "api-v6.example.net",
    "2001:4860:4860::8888",
    "resource[.]hyphen-site[.]com",
    "sub-domain[.]example-hyphen[.]org",
    "hyphen[.]example[.]co[.]uk",
    "docs-example.com",
    "support[.]hyphen-example[.]net",
    "2001:0db8:0000:0000:0000:8a2e:0370:7334",
    "hyphen-subdomain.example.com",
    "www[.]hyphen-site[.]org",
    "api.example-hyphen.com",
    "192.168.1.255",
    "hyphen-resource.example.net",
    "www[.]example-hyphen[.]co[.]uk",
    "subdomain[.]resource-hyphen[.]com",
    "2001:0db8:1234:0000:0000:8a2e:0370:7334",
    "test[.]hyphen[.]site[.]com",
    "hyphen-example[.]co[.]uk",
    "example-subdomain-hyphen.com",
    "resource[.]ipv6[.]site",
    "example[.]hyphen-resource[.]net",
    "2001:4860:4860::8844",
    "resource-hyphen[.]example[.]org",
    "sub-domain[.]example[.]hyphen",
    "hyphen-test[.]example[.]net",
    "2001:0db8:5678:0000:0000:8a2e:0370:7334",
    "www[.]sub-domain[.]hyphen[.]com",
    "test-site-hyphen.com",
    "example-resource-hyphen[.]org",
    "api[.]hyphen-site[.]net",
    "hyphen-site[.]example-hyphen[.]com",
    "2001:0db8:4321:0000:0000:8a2e:0370:7334",
    "resource-hyphen-example[.]org",
    "subdomain-hyphen-resource[.]com",
    "api-hyphen-resource[.]example[.]net",
    "test-hyphen[.]example-site[.]org",
    "resource[.]example-hyphen[.]com",
    "sub-domain[.]example-hyphen[.]net",
    "2001:0db8:8765:0000:0000:8a2e:0370:7334",
    "welcome to URls tou should block. PLease feel free to come back"
]

# Create a PDF document
pdf = PDF()
pdf.add_page()
pdf.set_font('Arial', '', 12)

# Add each URL or IP address to the PDF
for url in url_list:
    pdf.cell(0, 10, url, ln=True)

# Save the PDF to a file
pdf_file_path = 'ip_url_list.pdf'
pdf.output(pdf_file_path)



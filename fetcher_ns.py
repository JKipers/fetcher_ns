import dns.resolver
import requests
import re
from ipwhois import IPWhois

class Scanner:

    def __init__(self):
        self.user_input = input("Enter a domain name or IP address to look up: ")
        self.output_file = f"{self.user_input}_lookup_results.txt"
        self.ipinfo_token = ''  # Your ipinfo.io API key
        self.is_ip = self.is_valid_ip(self.user_input)
        self.perform_lookup()

    def is_valid_ip(self, ip):
        """Check if the input string is a valid IP address."""
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return pattern.match(ip) is not None

    def get_ip_details_ipinfo(self, ip):
        try:
            url = f"https://ipinfo.io/{ip}/json?token={self.ipinfo_token}"
            response = requests.get(url)
            data = response.json()
            asn = data.get('org', '').split()[0]  # ASN is usually the first part of the org field
            asn_description = data.get('org')
            city = data.get('city', 'Unknown City')
            region = data.get('region', 'Unknown Region')
            country = data.get('country', 'Unknown Country')
            location = f"{city}, {region}, {country}"
            hostname = data.get('hostname', 'No Hostname')
            return asn, asn_description, location, hostname
        except Exception as e:
            print(f"ipinfo.io lookup failed: {e}.")
            return None, None, "Unknown Location", "No Hostname"

    def get_ip_details_ipwhois(self, ip):
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            asn = results.get('asn')
            asn_description = results.get('asn_description')
            network = results.get('network', {})
            rir = network.get('rir')
            return asn, asn_description, rir
        except Exception as e:
            print(f"IPWhois lookup failed: {e}.")
            return None, None, None

    def write_to_file(self, record_type, value):
        with open(self.output_file, 'a') as f:
            f.write(f"{record_type}: {value}\n")

    def lookup_domain(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            print("\nStarting the A Record Scan\n")
            print("-" * 30)
            for rdata in answers:
                ip = rdata.address
                asn, asn_description, location, hostname = self.get_ip_details_ipinfo(ip)
                record = f"A Record: {ip} | Location: {location} | ASN: {asn} ({asn_description})"
                print(record)
                self.write_to_file('A Record', record)
            print("Completed A Record Scan Successfully...!\n")
        except Exception as e:
            print(f"Failed to resolve A records for {domain}: {e}")

        try:
            answers = dns.resolver.resolve(domain, 'MX')
            print("\nStarting the MX-Records Scan\n")
            print("-" * 30)
            for rdata in answers:
                record = f"MX Record: {rdata.exchange} | Priority: {rdata.preference}"
                print(record)
                self.write_to_file('MX Record', record)
            print("Completed the MX Records Scan Successfully...!\n")
        except Exception as e:
            print(f"Failed to resolve MX records for {domain}: {e}")

        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            print("\nStarting the AAAA Record Scan\n")
            print("-" * 30)
            for rdata in answers:
                record = f"AAAA Record: {rdata.address}"
                print(record)
                self.write_to_file('AAAA Record', record)
            print("Completed AAAA Record Scan Successfully\n")
        except Exception as e:
            print(f"Failed to resolve AAAA records for {domain}: {e}")

        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            print("\nStarting the TXT Record Scan\n")
            print("-" * 30)
            for rdata in answers:
                for txt_string in rdata.strings:
                    record = f"TXT Record: {txt_string.decode('utf-8')}"
                    print(record)
                    self.write_to_file('TXT Record', record)
            print("\nDNS Lookup scan Completed.\n")
        except Exception as e:
            print(f"Failed to resolve TXT records for {domain}: {e}")

    def lookup_ip(self, ip):
        print(f"\nStarting the IP Lookup for {ip}\n")
        print("-" * 30)
        self.write_to_file('IP Address', ip)

        # IPWhois lookup
        asn_whois, asn_description_whois, rir = self.get_ip_details_ipwhois(ip)
        print(f"IPWhois Details for {ip}:")
        print(f"ASN: {asn_whois}")
        print(f"ASN Description: {asn_description_whois}")
        print(f"RIR: {rir}")
        self.write_to_file('IPWhois ASN', asn_whois)
        self.write_to_file('IPWhois ASN Description', asn_description_whois)
        self.write_to_file('IPWhois RIR', rir)

        # ipinfo.io lookup
        asn_info, asn_description_info, location, hostname = self.get_ip_details_ipinfo(ip)
        print(f"IPInfo Details for {ip}:")
        print(f"Hostname: {hostname}")
        print(f"Location: {location}")
        print(f"ASN: {asn_info}")
        print(f"ASN Description: {asn_description_info}")
        self.write_to_file('IPInfo Hostname', hostname)
        self.write_to_file('IPInfo Location', location)
        self.write_to_file('IPInfo ASN', asn_info)
        self.write_to_file('IPInfo ASN Description', asn_description_info)

        print("\nIP Lookup Completed.\n")

    def perform_lookup(self):
        if self.is_ip:
            self.lookup_ip(self.user_input)
        else:
            self.lookup_domain(self.user_input)

if __name__ == "__main__":
    Scanner()

import wget
import os
import requests
import json
import time
import urllib.error

def get_nvd_feed():
    url = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip'
    max_retries = 5
    retry_delay = 60

    for attempt in range(max_retries):
        try:
            print(f"Attempt {attempt + 1} to download the file...")
            filename = wget.download(url)
            print(f"\nDownloaded {filename}")

            command = f'unzip -o {filename}'
            if os.system(command) != 0:
                raise Exception("Failed to unzip the file")

            unzipped_filename = 'nvdcve-2.0-modified.json'
            if not os.path.exists(unzipped_filename):
                raise FileNotFoundError(f"Unzipped file {unzipped_filename} not found")

            return unzipped_filename

        except urllib.error.HTTPError as e:
            if e.code == 503 and attempt < max_retries - 1:
                print(f"Service unavailable, retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                raise
        except Exception as e:
            print(f"An error occurred: {e}")
            raise

def get_cpes():
    with open('cpe.txt', 'r') as v:
        cpe = v.readlines()
        return cpe

def parse_nvd_feed(cpes):
    unzipped_filename = get_nvd_feed()
    with open(unzipped_filename, 'r') as f:
        cve_feed = json.load(f)

    cve_count = 0
    message = ""

    for vulnerability in cve_feed.get('vulnerabilities', []):
        cve = vulnerability.get('cve', {})
        id = cve.get('id', '')
        description = cve.get('descriptions', [{}])[0].get('value', 'No description available')

        try:
            configurations = cve.get('configurations', [])
            cpe_string = configurations[0]['nodes'][0]['cpeMatch'] if configurations else []
        except (KeyError, IndexError):
            cpe_string = []

        for line in cpes:
            for cpe in line.split():
                for match in cpe_string:
                    if cpe in match.get('criteria', ''):
                        message = message + slack_block_format(cpe, description, id)
                        cve_count += 1

    return message, cve_count

def slack_block_format(product, description, id):
    block = ',{"type": "section", "text": {"type": "mrkdwn","text": "*Product:* ' + product + '\n *CVE ID:* ' + id + '\n *Description:* ' + description + '\n "}}, {"type": "divider"}'
    return block

def send_slack_alert(message, cve_count):
    url = os.getenv('SLACK_WEBHOOK')
    slack_message = '{"blocks": [{"type": "section","text": {"type": "plain_text","emoji": true,"text": "Hello :wave:,'+ str(cve_count) +' Security Vulnerabilities affecting your Tech Stack were disclosed today."}}' + message + ']}'
    x = requests.post(url, data=slack_message)

def main():
    print("VulnAlerts Using GitHub Actions\n")
    message, cve_count = parse_nvd_feed(get_cpes())
    send_slack_alert(message, cve_count)
    print("Notification Sent")

if __name__ == '__main__':
    main()

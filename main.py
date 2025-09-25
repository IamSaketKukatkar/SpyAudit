from flask import Flask, request, jsonify, render_template_string
import requests
import base64
import time
import random
from urllib.parse import urlparse
import logging
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def read_html():
    try:
        with open('index.html', 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        logging.error("index.html file not found!")
        return "<h1>Error: index.html file not found!</h1>"

jaadu = read_html()


# main reversed part from virus total to makes sure the requests are not blocked by VirusTotal's anti-abuse measures
# this bypasses the x-vt-anti-abuse-header and makes the requests look more like a real browser
def computeAntiAbuseHeader():
    timestamp = int(time.time())
    rand_value = random.randint(10000000000, 99999999999)
    raw = f"{rand_value}-ZG9udCBiZSBldmls-{timestamp}"
    return base64.b64encode(raw.encode()).decode()

# function to get a random proxy from proxies.txt file for random ips and more realistic searchs
def get_random_proxy():
    proxies = []
    try:
        with open('proxies.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)
    except FileNotFoundError:
        logging.error("proxies.txt file not found")
        return None
    if not proxies:
        logging.error("No proxies found in proxies.txt")
        return None
    raw = random.choice(proxies)
    return f"http://{raw}"

# function to analyze a website using VirusTotal API with retries and proxy support
def analyze_website(url_input, max_retries=3):
    for attempt in range(max_retries):
        proxy_url = get_random_proxy()
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        
        headers = {
            'accept': 'application/json',
            'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
            'accept-language': 'en-US,en;q=0.5',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://www.virustotal.com/',
            'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Brave";v="138"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'x-app-version': 'v1x418x0',
            'x-tool': 'vt-ui-main',
            'x-vt-anti-abuse-header': computeAntiAbuseHeader(),
        }

        params = {
            'limit': '20',
            'query': url_input,
        }

        try:
            logging.info(f"Attempt {attempt+1}: Scanning {url_input}")
            response = requests.get(
                'https://www.virustotal.com/ui/search',
                params=params,
                headers=headers,
                proxies=proxies,
                timeout=15
            )
            
            logging.info(f"Status: {response.status_code}")
            
            if response.status_code != 200:
                logging.warning(f"Non-200 response: {response.status_code} - {response.text[:200]}")
                continue
                
            data = response.json()
          
            if "data" not in data or not data["data"]:
                logging.warning(f"No data in response: {data}")
                return None

            stats = data["data"][0]["attributes"]["last_analysis_stats"]
            threat_names = data["data"][0]["attributes"].get("threat_names", [])
            domain = urlparse(url_input).netloc

            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            total = harmless + undetected + malicious + suspicious
            if total > 0:
                score = 100 - (malicious * 100 / total) * 0.8 - (suspicious * 100 / total) * 0.4
            else:
                score = 100  

            score = max(0, min(100, int(score)))

            if score > 90:
                verdict = "SAFE"
            elif 85 <= score <= 90:
                verdict = "POTENTIALLY DANGEROUS"
            else:
                verdict = "UNSAFE"

            return {
                "domain": domain,
                "harmless": harmless,
                "undetected": undetected,
                "malicious": malicious,
                "suspicious": suspicious,
                "threat_names": threat_names,
                "verdict": verdict,
                "score": score
            }

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error: {str(e)}")
            time.sleep(2)
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            time.sleep(2)
            
    return None

# flask to serve the website and handle requests
@app.route('/audit', methods=['POST'])
def audit():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400

    vt_result = analyze_website(url)
    
    if not vt_result:
        return jsonify({"error": "Scan failed after multiple attempts. VirusTotal might be blocking requests."}), 500
    
    return jsonify({
        "domain": vt_result["domain"],
        "verdict": vt_result["verdict"],
        "threat_names": vt_result["threat_names"],
        "analysis_stats": {
            "harmless": vt_result["harmless"],
            "undetected": vt_result["undetected"],
            "malicious": vt_result["malicious"],
            "suspicious": vt_result["suspicious"]
        },
        "score": vt_result["score"]
    })

@app.route('/')
def index():
    return render_template_string(jaadu)

if __name__ == '__main__':
    app.run(debug=True, port=5000)  
import re
import base64
from lib.cuckoo.common.abstracts import Signature

class Base64Obfuscation(Signature):
    name = "base64_obfuscation_detected"
    description = "javascript code is obfuscated by base64 encoding"
    severity = 3
    confidence = 100
    categories = ["credential_access", "evasion", "infostealer", "phishing", "static"]
    authors = ["Yasin Tas", "Eye Security"]
    references = [
        "https://securelist.com/phishing-kit-market-whats-inside-off-the-shelf-phishing-packages/106149/",
        "https://socradar.io/what-is-a-phishing-kit/" "https://github.com/SteveD3/kit_hunter/tree/master/tag_files",
    ]
    enabled = True
    minimum = "1.2"
    ttps = ["T1111", "T1193", "T1140"]  # MITRE v6
    ttps += ["T1566.001"]  # MITRE v6,7,8
    ttps += ["T1606"]  # MITRE v7,8
    mbcs = ["C0029.003"]  # micro-behaviour
    packages = ["html", "edge", "chrome", "firefox"]

    def run(self):
        has_match = False

        if self.results["info"]["package"] in self.packages:
            strings = self.results["target"]["file"]["strings"]
            data = "".join(strings) if strings else self.results["target"]["file"]["data"]
            regex_decoded = [
                r"atob\(\s*\'([^&]+?)\'\s*\)",
                r"atob\(\s*\"([^&]+?)\"\s*\)",
            ]
            js_regex = r"/\b(function|var|let|const|if|else|for|while|do|switch|case|default|try|catch|finally|return|new|this|typeof|delete|in|instanceof)\b/"
            regex_phishingkit_values = [
                {'re': r"YOUR_BOT_TOKEN\s*=\s*\"([^&]+?)\"", 'name': 'Telegram Bot Token', 'group': 1},
                {'re': r"YOUR_BOT_TOKEN\s*=\s*\'([^&]+?)\'", 'name': 'Telegram Bot Token', 'group': 1},
                {'re': r"YOUR_CHANNEL_ID\s*=\s*\"([^&]+?)\"", 'name': 'Telegram Channel ID', 'group': 1},
                {'re': r"YOUR_CHANNEL_ID\s*=\s*\'([^&]+?)\'", 'name': 'Telegram Channel ID', 'group': 1},
            ]
            for regex in regex_decoded:
                decodeString = re.search(regex, data)
                if decodeString:
                    decodeString = decodeString.group(1)
                    decoded_string = base64.b64decode(decodeString).decode('utf-8')
                    has_js = re.search(js_regex, decodeString)
                    if has_js:
                        has_match = True

                        for phishing_re in regex_phishingkit_values:
                            hit = re.search(phishing_re['re'], decoded_string)
                            if hit:
                                if 'group' in phishing_re:
                                    self.data.append({phishing_re["name"]: hit.group(phishing_re['group'])})
                                else:
                                    self.data.append({'name': phishing_re["name"]})
        return has_match
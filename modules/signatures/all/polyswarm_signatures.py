from lib.cuckoo.common.abstracts import Signature

class CustomTestSignature(Signature):
    name = "test_signature"
    description = "testing"
    severity = 3
    confidence = 100
    categories = ["credential_access", "evasion", "infostealer", "phishing", "static"]
    authors = []
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

    def run(self):
        return True
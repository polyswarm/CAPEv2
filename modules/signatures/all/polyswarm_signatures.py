# Copyright (C) 2023 Eye Security (yasin.tas@eye.security)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import re

from lib.cuckoo.common.abstracts import Signature

class SuspiciousTelegram(Signature):
    name = "telegram_api_detected"
    description = "Sample contains suspicious telegram related code"
    severity = 3
    confidence = 100
    categories = ["credential_access", "evasion", "infostealer", "phishing", "static"]
    authors = ["Michael Bradford", "PolySwarm"]
    references = [
        "https://github.com/0xDanielLopez/phishing_kits"
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
        indicators = [
            "api.telegram.org",
            "api.telegram",
            "YXBpLnRlbGVncmFtLm9yZw==",
            "YXBpLnRlbGVncmFt",
            "YOUR_BOT_TOKEN",
            "1TAO UY1",
            "pr3xt4rs",
            "PR9345FW",
            "t0s24u824s",
            "bmV4dC5waHA=",
            "ZW1haWwucGhw",
        ]

        if self.results["info"]["package"] in self.packages:
            strings = self.results["target"]["file"]["strings"]
            data = "".join(strings) if strings else self.results["target"]["file"]["data"]
            for indicator in indicators:
                if indicator in data:
                    has_match = True
        return has_match

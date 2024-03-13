from lib.common.abstracts import Package


class Edge(Package):
    """Edge analysis package."""

    PATHS = [
        ("Users", "maxine", "Desktop", "Microsoft Edge.lnk")
    ]

    def start(self, url):
        edge = self.get_path("Microsoft Edge.lnk")
        args = [
            "file:///{}".format(url.replace('\\', '/')),
        ]
        args = " ".join(args)
        return self.execute(edge, args, url)

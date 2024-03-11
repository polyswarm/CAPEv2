from lib.common.abstracts import Package


class Edge(Package):
    """Edge analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
        ("ProgramFiles(x86)", "Microsoft", "EdgeCore", "112.0.1722.58", "msedge.exe")
    ]

    def start(self, url):
        edge = self.get_path("msedge.exe")
        args = [
            "--disable-features=RendererCodeIntegrity",
        ]
        args.append('"{}"'.format(url))
        args = " ".join(args)
        return self.execute(edge, args)

from lib.common.abstracts import Package


class Edge(Package):
    """Edge analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
        ("ProgramFiles(x86)", "Microsoft", "EdgeCore", "*", "msedge.exe"),
    ]
    summary = "Opens the URL in Microsoft Edge."
    description = """Uses msedge.exe to open the supplied url."""

    def start(self, url):
        edge = self.get_path_glob("msedge.exe")
        args = [
            "--disable-features=RendererCodeIntegrity",
            "--disable-extensions",
            "--no-first-run",
            "--no-default-browser-check",
            "--profile-directory=maxine",
        ]
        args.append('"{}"'.format(url))
        args = " ".join(args)
        return self.execute(edge, args, url)

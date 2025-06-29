import argparse
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gwifi-fp", description="Google/Nest WiFi fingerprinting tool")
    p.add_argument("target", help="IPv4/IPv6 address")
    p.add_argument("-m", "--module", action="append", help="Specific scanner modules to run")
    p.add_argument("--json-out", help="Write raw JSON results to file")
    p.add_argument("--interactive", action="store_true", help="Interactive menu")
    p.add_argument("--legal-ok", action="store_true", help="Affirm that you have legal authorization")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    return p

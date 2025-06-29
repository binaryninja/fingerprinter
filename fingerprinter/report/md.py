from fingerprinter.core.result import ScanReport

def render_markdown(r: ScanReport) -> str:
    md = [f"# Scan Report – {r.target}",
          f"*Started*: {r.started.isoformat()}",
          f"*Finished*: {r.finished}"]
    if r.ports:
        md.append("\n## Open Ports\n")
        for p in r.ports:
            banner = f" – _{p.banner[:60]}_" if p.banner else ""
            md.append(f"* **{p.port}/{p.proto}**{banner}")
            if p.raw_fingerprint:
                md.append(f"  \n  **Raw Fingerprint:**")
                md.append(f"```/dev/null/nmap_fingerprint.txt#L1-10")
                md.append(f"  {p.raw_fingerprint}")
                md.append(f"```")
    if r.http:
        md.append("\n## Web Services\n")
        for h in r.http:
            sig = f" ({', '.join(h.signatures)})" if h.signatures else ""
            md.append(f"* [{h.status}] {h.url} – **{h.title or 'n/a'}**{sig}")
    if r.notes:
        md.append("\n## Notes\n")
        md.extend([f"* {line}" for line in r.notes])
    return "\n".join(md)

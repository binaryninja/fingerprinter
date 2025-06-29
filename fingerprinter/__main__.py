import asyncio, json, sys
from pathlib import Path  # <== ADD THIS
from fingerprinter.cli import build_parser
from fingerprinter.core.context import ScanContext
from fingerprinter.core.logging import get_logger
from fingerprinter.scanners import run_scanners
from fingerprinter.report.md import render_markdown

def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    ctx = ScanContext(
        target=args.target,
        interactive=args.interactive,
        legal_ok=args.legal_ok)
    log = get_logger(args.verbose)

    if not ctx.legal_ok:
        log.error("Refusing to run without --legal-ok acknowledgement.")
        sys.exit(1)

    report = asyncio.run(run_scanners(ctx, args.module, log))

    out_fp = args.json_out or Path(ctx.json_out())
    out_fp.write_text(json.dumps(report.asdict(), indent=2, default=str))
    log.info(f"Wrote raw results → {out_fp}")

    print(render_markdown(report))

    if ctx.interactive:
        print("Interactive mode coming soon.")

if __name__ == "__main__":
    main()

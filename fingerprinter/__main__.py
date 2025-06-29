import asyncio
import json
import sys
from pathlib import Path
from fingerprinter.cli import build_parser, validate_args, create_scan_context_from_args, filter_compatible_scanners, print_usage_examples
from fingerprinter.core.logging import get_logger
from fingerprinter.scanners import run_scanners, available
from fingerprinter.report.md import render_markdown

def main(argv: list[str] | None = None) -> None:
    # Handle special commands before parsing
    if argv and len(argv) == 1 and argv[0] in ['examples', '--examples']:
        print_usage_examples()
        return

    # Handle examples command even without argv
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) == 1 and argv[0] in ['examples', '--examples']:
        print_usage_examples()
        return

    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle help requests
    if hasattr(args, 'help') and args.help:
        parser.print_help()
        print_usage_examples()
        return

    # Validate arguments
    valid, error_msg = validate_args(args)
    if not valid:
        print(f"Error: {error_msg}", file=sys.stderr)
        sys.exit(1)

    # Initialize logging
    log = get_logger(args.verbose)

    try:
        # Create scan context from arguments
        ctx = create_scan_context_from_args(args)
        log.info(f"Starting scan: {ctx.get_context_description()}")

        # Determine which scanners to run
        available_scanners = available()

        if args.module:
            # User specified specific modules
            requested_scanners = args.module

            # Filter for compatibility
            compatible_scanners, incompatible_scanners = filter_compatible_scanners(
                requested_scanners, ctx
            )

            if incompatible_scanners:
                log.warning(f"Skipping incompatible scanners for {ctx.target_type} target: {', '.join(incompatible_scanners)}")

            if not compatible_scanners:
                log.error(f"No compatible scanners found for {ctx.target_type} target")
                sys.exit(1)

            scanners_to_run = compatible_scanners

        else:
            # Auto-select compatible scanners
            scanners_to_run, incompatible = filter_compatible_scanners(available_scanners, ctx)

            if args.exclude_module:
                scanners_to_run = [s for s in scanners_to_run if s not in args.exclude_module]

            if incompatible:
                log.debug(f"Auto-excluded incompatible scanners: {', '.join(incompatible)}")

        if not scanners_to_run:
            log.error("No scanners selected to run")
            sys.exit(1)

        log.info(f"Running scanners: {', '.join(scanners_to_run)}")

        # Run the scan
        report = asyncio.run(run_scanners(ctx, scanners_to_run, log))

        # Generate output filename
        if args.json_out:
            out_fp = Path(args.json_out)
        else:
            out_fp = Path(ctx.json_out())

        # Write JSON results
        try:
            with open(out_fp, 'w') as f:
                json.dump(report.asdict(), f, indent=2, default=str)
            log.info(f"Wrote raw results → {out_fp}")
        except Exception as e:
            log.error(f"Failed to write JSON output: {e}")
            sys.exit(1)

        # Generate and display markdown report
        if not args.no_markdown:
            try:
                markdown_report = render_markdown(report)
                print(markdown_report)
            except Exception as e:
                log.error(f"Failed to generate markdown report: {e}")
                # Don't exit, JSON output is more important

        # Interactive mode
        if ctx.interactive:
            print("\n" + "="*60)
            print("Interactive Mode")
            print("="*60)
            print("Interactive analysis coming soon...")
            print("For now, review the JSON output and markdown report above.")

        # Print summary
        print(f"\nScan Summary:")
        print(f"- Target: {report.display_target}")
        print(f"- Scan ID: {report.scan_id}")
        if report.location:
            print(f"- Location: {report.location}")
        if report.is_network_scan:
            print(f"- Open Ports: {report.total_open_ports}")
            print(f"- HTTP Services: {len(report.http)}")
        if report.has_rf_data:
            total_rf_activity = sum(len(scan.hot_bins) for scan in report.rf_scans)
            print(f"- RF Activity: {total_rf_activity} active frequencies")
        print(f"- Duration: {(report.finished - report.started).total_seconds():.1f}s")

    except KeyboardInterrupt:
        log.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        log.error(f"Scan failed: {e}")
        if args.verbose >= 2:  # Debug mode
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

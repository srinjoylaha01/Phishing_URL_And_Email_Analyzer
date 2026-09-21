"""Phase 2 CLI bootstrap."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Defensive phishing URL and email security analyzer.",
    )
    parser.add_argument("--version", action="version", version="phishguard 0.1.0")
    return parser


def main() -> None:
    build_parser().parse_args()


if __name__ == "__main__":
    main()

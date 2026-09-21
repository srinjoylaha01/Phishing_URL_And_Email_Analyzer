from phishguard import __version__
from phishguard.cli import build_parser


def test_package_version() -> None:
    assert __version__ == "0.1.0"


def test_cli_parser() -> None:
    args = build_parser().parse_args([])
    assert args is not None

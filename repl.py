from sds import ECU_Mode, Service

from rich.text import Text
from rich.highlighter import RegexHighlighter


class MsgHighlighter(RegexHighlighter):
    base_style = "msg."
    highlights = [
        r"(?P<interface>\w+) (?P<ecu>[0-9A-F]+) (?P<size>\[\d+\]) (?P<data>([0-9A-F]{2} ?)+)$",
        r"(?P<service>[0-9A-F]{2}) (?P<mode>[0-9A-F]{2}) (?P<data>([0-9A-F]{2} ?)+)$",
    ]

import argparse
import csv
import subprocess
from sys import platform

from Parse.AppNetAuditFusion.auditparser.parse_event import parse_event
from Parse.AppNetAuditFusion.auditparser.read import read, read_ausearch
from Parse.AppNetAuditFusion.auditparser.utils import RESULT_KEYS


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_path", required=False, default="test/audit.log")
    parser.add_argument("-o", "--output_path", required=False, default="test.tsv")
    parser.add_argument("-f", "--filter_apps", required=False, default=None, nargs="+")
    return parser.parse_args()


def parse(
    input_path: str,
    output_path: str,
    keep_apps: set[str] | None,
    write_buffer_size: int = 10000,
):
    ans=[]
    mode = "normal"
    input_file = open(input_path, "r")
    resolved_input = ""
    if "linux" in platform:
        try:
            resolved_input = subprocess.check_output(
                ["ausearch", "-if", input_path, "-i"]
            ).decode()
            mode = "ausearch"
        except:
            pass

    with open(output_path, "w", encoding="utf8") as output_file:
        writer = csv.DictWriter(
            output_file, RESULT_KEYS, delimiter="\t", lineterminator="\n"
        )
        writer.writeheader()
        lines = []

        for event in (
            read_ausearch(resolved_input) if mode == "ausearch" else read(input_file)
        ):
            result_lines = parse_event(event, keep_apps, ausearch=mode == "ausearch")
            lines.extend(result_lines)

            if len(lines) >= 1.2 * write_buffer_size:  # 12000
                out_lines = lines[:write_buffer_size]
                lines = lines[write_buffer_size:]

                # 找到后面一节中时间早于分界点的行，拉到前面来
                max_timestamp: str = max(l["timestamp"] for l in out_lines)
                for l in lines.copy():
                    if l["timestamp"] <= max_timestamp:
                        out_lines.append(l)
                        lines.remove(l)

                writer.writerows(sorted(out_lines, key=lambda l: l["timestamp"]))
                ans = ans + sorted(out_lines, key=lambda l: l["timestamp"])

        writer.writerows(sorted(lines, key=lambda l: l["timestamp"]))
        ans = ans + sorted(lines, key=lambda l: l["timestamp"])

    input_file.close()
    return sorted(ans, key=lambda l: l["timestamp"])


if __name__ == "__main__":
    args = get_args()
    keep_apps: set[str] | None = set(args.filter_apps) if args.filter_apps else None
    parse(args.input_path, args.output_path, keep_apps)

"""
Make reports from mt file.
"""
import contextlib
import os
import signal
import sys
from pathlib import Path
from rich import print as rprint

from mt_parser import MTParser
from symbolizer import Symbolizer
import graph

class Report:
    """
    Make reports from mt file.
    """
    def __init__(self, mt_fname):
        self.parser = MTParser()
        self.parser.parse(mt_fname)
        self.mt_file = Path(mt_fname)

    def report_txt(self):
        """
        Make text report from mt file.
        """
        report = TxtReport(self.parser)
        report.report()

    def report_tree(self):
        """
        Make graph report from mt file.
        """
        tree = graph.FrameTree(self.parser)
        txt_file = self.mt_file.with_suffix('.txt')
        print(f"txt file is {txt_file}.")
        with open(txt_file, "w") as txt_file:
            rprint(tree.tree_to_rich(), file=txt_file)

    def report_flame(self):
        tree = graph.FrameTree(self.parser)
        template_name = Path(os.path.dirname(os.path.realpath(__file__))) / "template.html"
        with open(template_name, "r") as template_file:
            contents = template_file.readlines()

        line_num = [num for num, line in enumerate(contents) if "HERE" in line][0]
        contents.insert(line_num, tree.tree_to_json())

        flame = self.mt_file.with_suffix('.html')
        print(f"flame file is {flame}.")
        with open(flame, "w") as html_file:
            contents = "".join(contents)
            html_file.write(contents)


class TxtReport:
    """
    Make text report from mt file.
    """
    def __init__(self, storage):
        self.storage = storage

    def report_stack(self, symbolizer, stack_info):
        """
        Report allocation point. Allocation data and stack.

        :symbolizer: llvm symbolizer
        :stack_info: data about allocation point
        """
        memsize, cnt = stack_info.info.not_freed()
        if not memsize:
            return
        avg = int(memsize / cnt)
        print(f"Allocated {memsize} bytes in {cnt} allocations ({avg} bytes average)")
        output = symbolizer.symbolize(stack_info.stack, self.storage.mapper)
        print(output)

    def report(self):
        """
        Report all allocations.
        """
        with contextlib.closing(Symbolizer()) as symbolizer:
            for stack_info in self.storage.stacks_info:
                self.report_stack(symbolizer, stack_info)

            memsize, cnt = self.storage.stats.not_freed()
            print(f"Total: allocation {cnt} of total size {memsize}")

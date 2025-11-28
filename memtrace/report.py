"""
Make reports from mt file.
"""
import contextlib
import os
import signal
import sys
from pathlib import Path

from mt_parser import MTParser, Statistics
from symbolizer import Symbolizer
import graph

class Report:
    """
    Make reports from mt file.
    """
    def __init__(self, mt_fname, all, symbolizer_path):
        self.symbolizer_path = symbolizer_path
        self.parser = MTParser(all)
        self.parser.parse(mt_fname)
        self.mt_file = Path(mt_fname)
        self.all = all

    def report_txt(self):
        """
        Make text report from mt file.
        """
        report = TxtReport(self.parser, self.symbolizer_path)
        report.report(self.mt_file)

    def report_tree(self):
        """
        Make graph report from mt file.
        """
        from rich import print as rprint
        tree = graph.FrameTree(self.parser.stats, self.parser.stacks_info, self.parser.mapper, self.symbolizer_path)
        txt_file = self.mt_file.with_suffix('.txt')
        print(f"txt file is {txt_file}")
        with open(txt_file, "w") as txt_file:
            rprint(tree.tree_to_rich(), file=txt_file)

    def report_flame(self):
        tree = graph.FrameTree(self.parser.stats, self.parser.stacks_info, self.parser.mapper, self.symbolizer_path)
        fname = self.mt_file.with_suffix('.html')
        self.report_flame_tree(tree, fname)

        stats = Statistics(True, self.parser.stats.free_no_alloc, self.parser.stats.free_no_alloc_count)
        tree = graph.FrameTree(stats, self.parser.free_info, self.parser.mapper, self.symbolizer_path)
        fname = self.mt_file.with_stem(self.mt_file.stem + "_free").with_suffix('.html')
        self.mt_file.with_stem
        self.report_flame_tree(tree, fname)

    def report_flame_tree(self, tree, fname):
        template_name = Path(os.path.dirname(os.path.realpath(__file__))) / "template.html"
        with open(template_name, "r") as template_file:
            contents = template_file.readlines()

        tree_to_json = tree.tree_to_json()
        line_num = [num for num, line in enumerate(contents) if "HERE" in line][0]
        contents.insert(line_num, tree_to_json)

        tracing_info_str = self.parser.trace_info.to_text(end="<br/>")
        extra_data = f"<div>{tracing_info_str}</div>"
        line_num = [num + 1 for num, line in enumerate(contents) if "EXTRA DATA" in line][0]
        contents.insert(line_num, extra_data)

        print(f"flame file is {fname}")
        with open(fname, "w") as html_file:
            contents = "".join(contents)
            html_file.write(contents)

class TxtReport:
    """
    Make text report from mt file.
    """
    def __init__(self, parser, symbolizer_path):
        self.parser = parser
        self.symbolizer_path = symbolizer_path

    def report_stack(self, symbolizer, stack_info):
        """
        Report allocation point. Allocation data and stack.

        :symbolizer: llvm symbolizer
        :stack_info: data about allocation point
        """
        memsize, cnt = stack_info.info.not_freed()
        if not memsize:
            return ""
        avg = int(memsize / cnt)
        output = symbolizer.symbolize(stack_info.stack, self.parser.mapper)
        return f"Allocated {memsize:,} B in {cnt} allocations ({avg:,} B average)\n{output}\n"

    def report(self, mt_file):
        """
        Report all allocations.
        """
        with contextlib.closing(Symbolizer(self.symbolizer_path)) as symbolizer:
            text = ""
            for stack_info in self.parser.stacks_info:
                text += self.report_stack(symbolizer, stack_info)
            memsize, cnt = self.parser.stats.not_freed()
            text += f"Total: allocation {cnt} of total size {memsize:,} B\n\n"
            text += self.parser.trace_info.to_text()

            txt_file = mt_file.with_suffix('.txt')
            print(f"txt file is {txt_file}")
            with open(txt_file, "w") as txt_file:
                txt_file.write(text)

            text = "FREE WITHOUT ALLOCATION\n"
            for free_info in self.parser.free_info:
                text += self.report_stack(symbolizer, free_info)
            free_mem, free_count = self.parser.stats.freed_no_alloc()
            text += f"Free without allocation {free_count} of size {free_mem:,} B\n\n"
            text += self.parser.trace_info.to_text()

            txt_file = mt_file.with_stem(mt_file.stem + "_free").with_suffix('.txt')
            print(f"txt file is {txt_file}")
            with open(txt_file, "w") as txt_file:
                txt_file.write(text)

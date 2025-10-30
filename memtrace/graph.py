"""
Make tree from mt file.
"""
import contextlib
import os
import signal
import sys

from pathlib import Path

from mt_parser import MTParser
from symbolizer import Symbolizer

class MemFrame:
    def __init__(self, name, name_index, parent, index, info):
        self.name = name
        self.name_index = name_index
        self.parent = parent
        self.index = index
        self.children = []
        self.memsize = 0
        self.cnt = 0
        self.add_info(info)

    def add_info(self, info):
        memsize, cnt = info.not_freed()
        self.memsize += memsize
        self.cnt += cnt

    def add_child(self, frame):
        self.children.append(frame)


class FrameTree:
    def __init__(self, stats, stacks_info, mapper, symbolizer_path, max_length=129):
        self.stacks_info = stacks_info
        self.mapper = mapper
        self.tree = [[] for _ in range(max_length)]
        self.names = []
        self.append_frame(" root", 0, stats)

        with contextlib.closing(Symbolizer(symbolizer_path, prefix=" ")) as symbolizer:
            root = self.tree[0][0]
            for info in self.stacks_info:
                memsize, _cnt = info.info.not_freed()
                if memsize:
                    stack_str = symbolizer.symbolize(reversed(info.stack), self.mapper)
                    stack = stack_str.rstrip().split("\n")
                    self.insert(stack, info.info, self.tree[1], 1, root)

    def append_frame(self, name, level, info, parent=None):
        name_index = len(self.names)
        self.names.append(name.strip())
        frame = MemFrame(name, name_index, parent, len(self.tree[level]), info)
        self.tree[level].append(frame)
        if parent:
            parent.add_child(frame)
        return frame

    def insert(self, stack, info, nodes, level, parent):
        if not stack:
            return

        for node in nodes:
            if node.name == stack[0]:
                node.add_info(info)
                self.insert(stack[1:], info, node.children, level+1, node)
                return

        for fname in stack:
            parent = self.append_frame(fname, level, info, parent)
            level += 1

    def tree_to_rich(self):
        from rich.tree import Tree
        rich_tree = Tree(f":deciduous_tree: Memory tree:", guide_style="bold bright_blue")
        self.node_to_rich(rich_tree, self.tree[0][0])
        return rich_tree

    def node_to_rich(self, rich_tree, node):
        value = f":herb: {node.memsize} bytes\n{node.name}\n"
        while len(node.children) == 1:
            node = node.children[0]
            value += f"{node.name}\n"
        rich_tree = rich_tree.add(value)

        for ch in node.children:
            self.node_to_rich(rich_tree, ch)

    def tree_to_json(self):
        # let names = ["null", "one", "two", "three", "four", "five"];
        # let treeLevels = [
        # [{ b: 24, cnt: 1, n: 0, ch: [0, 1], p: 0 } ],
        # [{ b: 12, cnt: 1, n: 1, ch: [0], p: 0 }, { b: 12, cnt: 1, n: 2, ch: [], p: 0 } ],
        # [{ b: 2, cnt: 3, n: 3, ch: [], p: 0 }],
        # ];
        tree_as_json = "let treeLevels = [\n"
        tree_as_json += "".join([self.level_to_json(level) for level in self.tree if level])
        tree_as_json += "".join(f"];\nlet names = {self.names};\n")
        return tree_as_json

    def level_to_json(self, level):
        level_as_json = "["
        level_as_json += "".join([self.node_to_json(node) for node in level])
        level_as_json += "".join("],\n")
        return level_as_json

    def node_to_json(self, node):
        parent_index = node.parent.index if node.parent else 0
        children = [ch.index for ch in node.children]
        return f"{{ b: {node.memsize}, cnt: {node.cnt}, n: {node.name_index}, ch: {children}, p: {parent_index} }},"

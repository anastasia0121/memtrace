"""
Make tree from mt file.
"""
import contextlib
import os
import signal
import sys

from rich.tree import Tree
from rich import print

from mt_parser import MTParser
from symbolizer import Symbolizer

class MemFrame:
    def __init__(self, name, parent, index, info):
        self.name = name
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
    def __init__(self, storage, max_length=128):
        self.storage = storage
        self.tree = [[] for _ in range(max_length)]
        self.append_frame(0, 0, self.storage.stats)

        root = self.tree[0][0]
        for info in self.storage.stacks_info:
            memsize, _cnt = info.info.not_freed()
            if memsize:
                info.stack.reverse()
                self.insert(info.stack, info.info, self.tree[1], 1, root)

    def append_frame(self, name, level, info, parent=None):
        frame = MemFrame(name, parent, len(self.tree[level]), info)
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

    def out(self):
        out_tree = Tree(f"🌳 Memory tree:", guide_style="bold bright_blue")
        with contextlib.closing(Symbolizer(prefix=" ")) as symbolizer:
            self.add_node(out_tree, self.tree[0][0], symbolizer)
        print(out_tree)

    def add_node(self, parent, node, symbolizer):
        value = f"🌿 {node.memsize} bytes\n"
        value += symbolizer.symbolize_addr(node.name, self.storage.mapper)
        while len(node.children) == 1:
            node = node.children[0]
            value += symbolizer.symbolize_addr(node.name, self.storage.mapper)

        parent = parent.add(value)

        for ch in node.children:
            self.add_node(parent, ch, symbolizer)

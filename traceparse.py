#!/usr/bin/env python
import os
import pickle
from argparse import ArgumentParser
from collections import Counter
from multiprocessing.pool import Pool
from typing import List, Optional

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.hop import ICMPType, Hop
from traceutils.scamper.warts import WartsReader

_ip2as: Optional[IP2AS] = None

class Info:
    def __init__(self):
        self.addrs = Counter()
        self.tuples = Counter()

    def __repr__(self):
        return 'Addrs {:,d} Adjs {:,d}'.format(len(self.addrs), len(self.tuples))

    @classmethod
    def load(cls, file):
        with open(file, 'rb') as f:
            d = pickle.load(f)
        info = Info()
        info.addrs = d['addrs']
        info.tuples = d['tuples']
        return info

    def dump(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(vars(self), f)

    def update(self, info):
        self.addrs.update(info.addrs)
        self.tuples.update(info.tuples)


def candidates_parallel(files: List[str], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    info = Info()
    pb = Progress(len(files), message='Parsing traceroutes', callback=lambda: '{}'.format(info))
    with Pool(poolsize) as pool:
        for newinfo in pb.iterator(pool.imap(candidates, files)):
            info.update(newinfo)
    return info

def candidates(filename, ip2as: IP2AS = None, info: Info = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = Info()
    with WartsReader(filename) as f:
        for trace in f:
            if trace.hops:
                trace.prune_private(_ip2as)
                if trace.hops:
                    trace.prune_dups()
                    info.addrs.update(h.addr for h in trace.hops)
                    trace.prune_loops()
                    if trace.hops:
                        for i in range(len(trace.hops) - 1):
                            x: Hop = trace.hops[i]
                            y: Hop = trace.hops[i+1]
                            xaddr = x.addr
                            yaddr = y.addr
                            if x.probe_ttl == y.probe_ttl - 1:
                                if y.type != ICMPType.echo_reply:
                                    info.tuples[xaddr, yaddr] += 1
    return info

def main():
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=40)
    args = parser.parse_args()
    files = []
    with File2(args.filename) as f:
        for line in f:
            line = line.strip()
            files.append(line)
    print('Files: {:,d}'.format(len(files)))
    ip2as = IP2AS()
    ip2as.add_private()
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    info = candidates_parallel(files, ip2as=ip2as, poolsize=args.poolsize)
    info.dump(args.output)

if __name__ == '__main__':
    main()

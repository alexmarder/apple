#!/usr/bin/env python
import os
from argparse import ArgumentParser
from multiprocessing.pool import Pool
from typing import List, Optional, Set, Tuple

from traceutils.file2 import fopen2
from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.hop import ICMPType, Hop
from traceutils.scamper.warts import WartsReader

_ip2as: Optional[IP2AS] = None

def candidates_parallel(files: List[str], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    info = set()
    pb = Progress(len(files), message='Parsing traceroutes', callback=lambda: 'Adjacencies {}'.format(len(info)))
    with Pool(poolsize) as pool:
        for newinfo in pb.iterator(pool.imap(candidates, files)):
            info.update(newinfo)
    return info

def candidates(filename, ip2as: IP2AS = None, info: Set[Tuple[str, str]] = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = set()
    with WartsReader(filename) as f:
        for trace in f:
            if trace.hops:
                trace.prune_private(_ip2as)
                if trace.hops:
                    trace.prune_dups()
                    trace.prune_loops(keepfirst=True)
                    if trace.hops:
                        for i in range(len(trace.hops) - 1):
                            x: Hop = trace.hops[i]
                            y: Hop = trace.hops[i+1]
                            xaddr = x.addr
                            yaddr = y.addr
                            if x.probe_ttl == y.probe_ttl - 1:
                                if y.type != ICMPType.echo_reply:
                                    info.add((xaddr, yaddr))
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
    with fopen2(args.output, 'wt') as f:
        for x, y in info:
            f.write('{}\t{}\n'.format(x, y))

if __name__ == '__main__':
    main()

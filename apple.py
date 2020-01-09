#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import defaultdict
from itertools import combinations
from multiprocessing.pool import Pool
import networkx as nx

from traceutils.file2.file2 import File2
from traceutils.progress import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader

def read(filename):
    d = {}
    with WartsReader(filename) as f:
        for r in f:
            for resp in r.responses:
                if resp.type == ICMPType.echo_reply:
                    d[r.dst] = resp.reply_ttl
                    break
    return filename, d

def read_pings(files, poolsize=25):
    rttls = defaultdict(dict)
    pb = Progress(len(files), 'Reading ping results', callback=lambda: '{:,d}'.format(len(rttls)))
    with Pool(poolsize) as pool:
        for filename, d in pb.iterator(pool.imap_unordered(read, files)):
            for a, ttl in d.items():
                rttls[a][filename] = ttl
    rttls.default_factory = None
    return rttls

def create_prevs(tuples):
    prevs = defaultdict(set)
    pb = Progress(len(tuples), 'Reading tuples', increment=500000,
                  callback=lambda: 'P {:,d}'.format(len(prevs)))
    for x, y in pb.iterator(tuples):
        prevs[y].add(x)
    prevs.default_factory = None
    return prevs

def compare(rttls, x, y, mincommon=5):
    same = 0
    common = 0
    if x in rttls and y in rttls:
        d1 = rttls[x]
        d2 = rttls[y]
        if d1 and d2:
            for k, xres in d1.items():
                yres = d2.get(k)
                if yres:
                    common += 1
                    if xres == yres:
                        same += 1
    if common >= mincommon:
        return same / common if common > 0 else 0
    return -1

def readfiles(filename):
    files = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if line:
                if not line.startswith('#'):
                    files.append(line)
    return files

def readadjs(filename):
    adjs = set()
    with File2(filename) as f:
        for line in f:
            adj = tuple(line.split())
            adjs.add(adj)
    return adjs

def main():
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--files')
    group.add_argument('-F', '--filelist', nargs='+')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--adjs')
    group.add_argument('-l', '--loop')
    group.add_argument('-g', '--groups')
    parser.add_argument('-p', '--poolsize', type=int, default=25)
    parser.add_argument('-o', '--output')
    parser.add_argument('-t', '--threshold', type=float, default=.85)
    parser.add_argument('-c', '--common', type=int, default=5)
    args = parser.parse_args()

    if args.files:
        files = readfiles(args.files)
    else:
        files = args.filelist
    poolsize = min(args.poolsize, len(files))
    if args.groups:
        groups = []
        with open(args.groups) as f:
            for line in f:
                group = set(line.split())
                groups.append(group)
    else:
        if args.adjs:
            adjs = readadjs(args.adjs)
            print(len(adjs))
        elif args.loop:
            with open(args.loop, 'rb') as f:
                loop = pickle.load(f)
                loops = loop['loop']
                adjs = {t for t, n in loop['adjs'].items() if (n * 2) > loops[t]}                
        prevs = create_prevs(adjs)
        groups = list(prevs.values())
    rttls = read_pings(files, poolsize=poolsize)
    g = nx.Graph()
    pb = Progress(len(groups), 'Creating graph', increment=10000)
    for group in pb.iterator(groups):
        for x, y in combinations(group, 2):
            ratio = compare(rttls, x, y, mincommon=args.common)
            if ratio >= args.threshold:
                g.add_edge(x, y)
    with File2(args.output, 'wt') as f:
        for i, group in enumerate(sorted(nx.connected_components(g), key=-len), 1):
            f.write('node N{}:  {}\n'.format(i, ' '.join(group)))

if __name__ == '__main__':
    main()

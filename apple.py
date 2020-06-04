#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import defaultdict, Counter
from itertools import combinations
from math import floor
from multiprocessing.pool import Pool
import networkx as nx
import numpy as np
from traceutils.file2 import fopen2

from traceutils.file2.file2 import File2
from traceutils.progress import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader

def birthday(a, r, v):
    return 1 - np.exp(-a/(np.power(r, v)))

def read(filename):
    d = {}
    with WartsReader(filename) as f:
        for r in f:
            for resp in r.responses:
                if resp.type == ICMPType.echo_reply:
                    d[r.dst] = {'rttl': resp.reply_ttl, 'rtt': resp.rtt}
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

class Compare:
    def __init__(self, aliaspairs, rttls, mimatch, acceptance):
        self.aliaspairs = aliaspairs
        self.rttls = rttls
        self.minmatch = mimatch
        self.acceptance = acceptance

    def compare(self, x, y):
        d1 = self.rttls.get(x)
        d2 = self.rttls.get(y)
        if d1 and d2:
            keys = d1.keys() & d2.keys()
            keys = sorted(keys, key=lambda key: min(d1[key]['rtt'], d2[key]['rtt']))
            same = 0
            common = 0
            for k in keys:
                common += 1
                xres = d1[k]
                yres = d2[k]
                if xres['rttl'] == yres['rttl']:
                    same += 1
                    if same == self.minmatch:
                        break
            if same != self.minmatch:
                return False
            ratio = same / common if common > 0 else 0
            return ratio >= self.acceptance
        return False

    def infer_aliases(self, output):
        g = nx.Graph()
        pb = Progress(len(self.aliaspairs), 'Creating graph', increment=10000)
        for x, y in pb.iterator(self.aliaspairs):
            if self.compare(x, y):
                g.add_edge(x, y)
        with fopen2(output, 'wt') as f:
            f.write('# alias pairs: {}\n'.format(len(self.aliaspairs)))
            f.write('# minimum match: {}\n'.format(self.minmatch))
            f.write('# acceptance: {}\n'.format(self.acceptance))
            for i, group in enumerate(nx.connected_components(g), 1):
                f.write('node N{}:  {}\n'.format(i, ' '.join(group)))

def main():
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--files')
    group.add_argument('-F', '--filelist', nargs='+')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--adjs')
    parser.add_argument('-p', '--poolsize', type=int, default=25)
    parser.add_argument('-o', '--output')
    args = parser.parse_args()

    if args.files:
        files = readfiles(args.files)
    else:
        files = args.filelist
    poolsize = min(args.poolsize, len(files))
    rttls = read_pings(files, poolsize=poolsize)
    rttl_counter = defaultdict(Counter)
    for infos in rttls.values():
        for file, d in infos.items():
            rttl_counter[file][d['rttl']] += 1
    for file in files:
        c = rttl_counter[file]
        if sum(c.values()) < 100:
            del rttl_counter[file]
        elif max(c.values()) / sum(c.values()) > .5:
            del rttl_counter[file]
    r = floor(1 / max(max(c.values()) / sum(c.values()) for c in rttl_counter.values()))
    print('r={}'.format(r))
    adjs = readadjs(args.adjs)
    prevs = create_prevs(adjs)
    # groups = list(prevs.values())
    pairs = {(x1, x2) for group in prevs.values() for x1, x2 in combinations(group, 2)}
    a = len(pairs)
    print('a={}, r={}'.format(a, r))
    v = 1
    while birthday(a, r, v) >= 1/a:
        v += 1
    print('Set v={}'.format(v))
    # g = nx.Graph()
    # pb = Progress(len(groups), 'Creating graph', increment=10000)
    # for group in pb.iterator(groups):
    #     for x, y in combinations(group, 2):
    #         ratio = compare(rttls, x, y, mincommon=args.common)
    #         if ratio >= args.threshold:
    #             g.add_edge(x, y)
    # with File2(args.output, 'wt') as f:
    #     for i, group in enumerate(sorted(nx.connected_components(g), key=lambda x: (-len(x), x)), 1):
    #         f.write('node N{}:  {}\n'.format(i, ' '.join(group)))

if __name__ == '__main__':
    main()

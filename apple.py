#!/usr/bin/env python
import pickle
from argparse import ArgumentParser
from collections import defaultdict, Counter
from itertools import combinations
from multiprocessing.pool import Pool
import networkx as nx
from scipy.special import comb

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
                    d[r.dst] = {'rttl': resp.reply_ttl, 'rtt': resp.rtt}
                    continue
    return filename, d

def read_pings(files, poolsize=25):
    rttls = defaultdict(dict)
    pb = Progress(len(files), 'Reading ping results', callback=lambda: '{:,d}'.format(len(rttls)))
    with Pool(poolsize) as pool:
        for filename, d in pb.iterator(pool.imap_unordered(read, files)):
            for a, info in d.items():
                rttls[a][filename] = info
    rttls.default_factory = None
    return rttls

def create_prevs(tuples, include=None):
    prevs = defaultdict(set)
    pb = Progress(len(tuples), 'Reading tuples', increment=500000, callback=lambda: '{:,d}'.format(len(prevs)))
    for x, y in pb.iterator(tuples):
        if include is None or x in include:
            prevs[y].add(x)
    prevs.default_factory = None
    return prevs

def compare(rttls, x, y, target, allowless=False):
    d1 = rttls.get(x)
    d2 = rttls.get(y)
    if d1 and d2:
        keys = d1.keys() & d2.keys()
        if len(keys) >= target or allowless:
            keys = sorted(keys, key=lambda key: min(d1[key]['rtt'], d2[key]['rtt']))
            same = 0
            common = 0
            for k in keys:
                common += 1
                xres = d1[k]
                yres = d2[k]
                if xres['rttl'] == yres['rttl']:
                    same += 1
                    if same == target:
                        break
            if same >= target or (allowless and same == common):
                ratio = same / common if common > 0 else 0
                return ratio
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

def create_graph(groups, rttls, acct):
    g = nx.Graph()
    pb = Progress(len(groups), 'Creating graph', increment=10000)
    for group in pb.iterator(groups):
        for x, y in combinations(group, 2):
            ratio = compare(rttls, x, y, mincommon=args.common)
            if ratio >= acct:
                g.add_edge(x, y)

def comb_pairs(groups):
    return {frozenset(t) for group in groups if len(group) > 1 for t in combinations(group, 2)}

def create_rttl_counter(rttls):
    counters = defaultdict(Counter)
    pb = Progress(len(rttls), 'Creating reply TTL counters', increment=10000)
    for addr, vprttls in pb.iterator(rttls.items()):
        for vp, d in vprttls.items():
            counters[vp][d['rttl']] += 1
    counters.default_factory = None
    return counters

def main():
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--files')
    group.add_argument('-F', '--filelist', nargs='+')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--adjs')
    group.add_argument('-l', '--loop')
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
    if args.adjs:
        adjs = readadjs(args.adjs)
        print(len(adjs))
    else:
        with open(args.loop, 'rb') as f:
            loop = pickle.load(f)
            loops = loop['loop']
            adjs = {t for t, n in loop['adjs'].items() if (n * 2) > loops[t]}
    rttls = read_pings(files, poolsize=poolsize)
    prevs = create_prevs(adjs)
    groups = [{a for a in group if a in rttls} for group in prevs.values()]
    groups = [group for group in groups if len(group) > 1]
    g = nx.Graph()
    pb = Progress(len(prevs), 'Creating graph', increment=10000)
    for group in pb.iterator(prevs.values()):
        for x, y in combinations(group, 2):
            ratio = compare(rttls, x, y, mincommon=args.common)
            if ratio >= args.threshold:
                g.add_edge(x, y)
    with File2(args.output, 'wt') as f:
        for i, group in enumerate(nx.connected_components(g), 1):
            f.write('node N{}:  {}\n'.format(i, ' '.join(group)))

if __name__ == '__main__':
    main()

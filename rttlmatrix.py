import os
from collections import defaultdict
from multiprocessing.pool import Pool

import pandas as pd
from traceutils.progress.bar import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader


# def read(file):
#     vp = os.path.basename(file).partition('.')[0]
#     rows = []
#     with WartsReader(file) as f:
#         for r in f:
#             for resp in r.responses:
#                 if resp.type == ICMPType.echo_reply:
#                     # row = pd.Series({'rttl': resp.reply_ttl, 'rtt': resp.rtt, 'vp': vp}, name=r.dst)
#                     # row = [r.dst, resp.reply_ttl, resp.rtt, vp]
#                     row = [r.dst, 'rttl', resp.reply_ttl]
#                     rows.append(row)
#                     row = [r.dst, 'rtt', resp.rtt]
#                     rows.append(row)
#     # return pd.DataFrame(rows, columns=['addr', 'rttl', 'rtt', 'vp']).set_index('addr')
#     return pd.DataFrame(rows, columns=['addr', 'vtype', vp]).set_index(['addr', 'vtype'])
#     # return pd.DataFrame(rows)

def read(filename):
    d = []
    vp = os.path.basename(filename).partition('.')[0]
    with WartsReader(filename) as f:
        for r in f:
            for resp in r.responses:
                if resp.type == ICMPType.echo_reply:
                    d.append([r.dst, resp.reply_ttl, resp.rtt, vp])
    return d

def read_pings(files, poolsize=25):
    rttls = []
    pb = Progress(len(files), 'Reading ping results', callback=lambda: '{:,d}'.format(len(rttls)))
    with Pool(poolsize) as pool:
        for d in pb.iterator(pool.imap_unordered(read, files)):
            rttls.extend(d)
    return rttls

def readdf(filename):
    d = []
    vp = os.path.basename(filename).partition('.')[0]
    with WartsReader(filename) as f:
        for r in f:
            for resp in r.responses:
                if resp.type == ICMPType.echo_reply:
                    d.append([r.dst, resp.reply_ttl, resp.rtt, vp])
    return pd.DataFrame(d, columns=['addr', 'rttl', 'rtt', 'vp'])

def read_pingsdf(files, poolsize=25):
    rttls = []
    pb = Progress(len(files), 'Reading ping results', callback=lambda: '{:,d}'.format(len(rttls)))
    with Pool(poolsize) as pool:
        for d in pb.iterator(pool.imap_unordered(readdf, files)):
            rttls.append(d)
    return pd.concat(rttls)

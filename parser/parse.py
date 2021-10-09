import math
import multiprocessing
import os
import re

import argparse
import time
import traceback
from multiprocessing import Process, Queue

from netaddr import iprange_to_cidrs, IPNetwork

from irrator.dumps import DumpManager
from loguru import logger

from postgres import setup_connection, Block, ASN

NUM_WORKERS = multiprocessing.cpu_count() * 2


def get_source(filename: str):
    if filename.startswith('afrinic'):
        return b'afrinic'
    elif filename.startswith('apnic'):
        return b'apnic'
    elif filename.startswith('arin'):
        return b'arin'
    elif filename.startswith('lacnic'):
        return b'lacnic'
    elif filename.startswith('ripe'):
        return b'ripe'
    elif filename.startswith('delegated-arin'):
        return b'd-arin'
    elif filename.startswith('delegated-ripencc'):
        return b'd-ripencc'
    elif filename.startswith('delegated-afrinic'):
        return b'd-afrinic'
    elif filename.startswith('delegated-apnic'):
        return b'd-apnic'
    elif filename.startswith('delegated-lacnic'):
        return b'd-lacnic'
    else:
        logger.error(f"Can not determine source for {filename}")
    return None


def parse_inetnum(inetnum: str) -> str:
    # IPv4 "192.168.0.1 - 192.168.255.255"
    match = re.findall(
        r'^((?:\d{1,3}\.){3}\d{1,3})[\s]*-[\s]*((?:\d{1,3}\.){3}\d{1,3})$', inetnum)
    if match:
        ip_start = match[0][0]
        ip_end = match[0][1]
        cidrs = iprange_to_cidrs(ip_start, ip_end)
        return cidrs
    # CIDR lacnic short x.x/22
    match = re.findall(
        r'^((?:\d{1,3}\.\d{1,3}(?:/\d{1,2}|)))$', inetnum)
    if match:
        cidr = match[0]
        return IPNetwork(cidr).cidr
    # CIDR lacnic short x.x.x/22
    match = re.findall(
        r'^((?:\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)))$', inetnum)
    if match:
        cidr = match[0]
        return IPNetwork(cidr).cidr
    # CIDR lacnic
    match = re.findall(
        r'^((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)))$', inetnum)
    if match:
        cidr = match[0]
        return IPNetwork(cidr).cidr
    # CIDR
    match = re.findall(r'^((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2}|))', inetnum)
    if match:
        cidr = match[0]
        return IPNetwork(cidr).cidr
    # IPv6
    match = re.findall(
        r'^([0-9a-fA-F:\/]{1,43})$', inetnum)
    if match:
        cidr = match[0]
        return IPNetwork(cidr).cidr
    # LACNIC translation for IPv4
    match = re.findall(
        r'^((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})$', inetnum)
    if match:
        cidr = match[0]
        return IPNetwork(cidr).cidr
    logger.warning(f"Could not parse inetnum on block {inetnum}")
    return None


def parse_country(block: dict, origin: str) -> str:
    if 'country' in block:
        return block['country']
    elif origin is not None and origin[:2] == 'AS':
        match = ASN_lists.get(origin, 'None')
        if match is not None:
            return match[1]
    else:
        return None


def read_blocks(path: str) -> list:
    logger.debug(f"opening {path} file")
    blocks = []
    cust_source = get_source(path.split('/')[-1])

    with open(path, mode='rb') as f:
        # Translation for extended
        if path.endswith('-extended-latest'):
            for line in f:
                line = line.strip()
                if line.startswith(b'arin') or line.startswith(b'ripencc') or line.startswith(
                        b'afrinic') or line.startswith(b'apnic') or line.startswith(b'lacnic'):
                    elements = line.split(b'|')
                    if len(elements) >= 7:
                        # convert lacnic to ripe format
                        single_block = b''
                        if elements[2] == b'ipv4':
                            single_block += b'inet4num: %s/%d\n' % (
                                elements[3], int(math.log(4294967296 / int(elements[4]), 2)))
                        elif elements[2] == b'ipv6':
                            single_block += b'inet6num: %s/%s\n' % (
                                elements[3], elements[4])
                        else:
                            if elements[2] == b'asn':
                                single_block += b"asn: %s\n" % elements[3]
                                if len(elements[1]) > 1:
                                    single_block += b'country: %s\n' % (elements[1])
                                if elements[5].isdigit():
                                    single_block += b'last-modified: %s\n' % (
                                        elements[5])
                                if len(elements) == 8 and elements[-1]:
                                    single_block += b'uid: %s\n' % elements[7]
                                single_block += b'descr: %s\n' % (elements[6])
                                if not any(x in single_block for x in [b'inet4num', b'inet6num', b'asn']):
                                    logger.warning(
                                        f"Invalid block: {line} {single_block}")
                                    continue
                                else:
                                    single_block += b"cust_source: %s" % cust_source
                                    yield single_block
                            else:
                                logger.warning(
                                    f"Unknown type {elements[2]} on line {line}")
                            continue
                        if len(elements[1]) > 1:
                            single_block += b'country: %s\n' % (elements[1])
                        if elements[5].isdigit():
                            single_block += b'last-modified: %s\n' % (
                                elements[5])
                        if len(elements) == 8 and elements[-1]:
                            single_block += b'uid: %s\n' % elements[7]
                        single_block += b'descr: %s\n' % (elements[6])
                        if not any(x in single_block for x in [b'inet4num', b'inet6num']):
                            logger.warning(
                                f"Invalid block: {line} {single_block}")
                        single_block += b"cust_source: %s" % cust_source
                        yield single_block
                    else:
                        logger.warning(f"Invalid line: {line}")
                else:
                    logger.warning(f"line does not start as expected: {line}")

        else:
            single_block = b''
            counter = 0
            for line in f:
                # skip comments
                if line.startswith(b'%') or line.startswith(b'#') or line.startswith(b'remarks:'):
                    continue
                # block end
                if line.strip() == b'':
                    if single_block != b'':
                        single_block += b"cust_source: %s" % cust_source
                        block = single_block
                        single_block = b''
                        if not any([x in block for x in [b'inetnum', b'inet6num', b'route', b'inet4num', b'route6']]):
                            continue
                        if counter % 5000 == 0:
                            logger.debug(
                                f"parsed another 5000 blocks")
                        counter += 1
                        yield block
                    # comment out to only parse x blocks
                    # if len(blocks) == 100:
                    #    break

                else:
                    if line.startswith(b' '):
                        single_block = single_block[:-1] + b' ' + line
                    else:
                        single_block += line


def publisher(jobs: Queue, path: str):
    blocks_generator = read_blocks(path)
    try:
        for block in blocks_generator:
            while True:
                if jobs.qsize() < 10000:
                    jobs.put(block)
                    break
                else:
                    time.sleep(1)
        for i in range(NUM_WORKERS - 1):
            jobs.put(None)
    except Exception as e:
        print(traceback.format_exc())


def subscriber(jobs: Queue, name, cs):
    counter = 0
    BLOCKS_DONE = 0
    COMMIT_COUNT = 2000

    session = setup_connection(cs)

    data = []
    in_ids = dict()
    asn_ids = dict()

    start_time = time.time()

    while True:
        try:
            block = jobs.get(timeout=600)
        except:
            break
        if block is None:
            break
        try:
            block = block.decode('latin-1')
        except:
            logger.error('Ooops... Can\'t decode line')
            with open(f"errors/decode.txt", "ab+") as ff:
                ff.write(block)
                ff.write(b"\n\n")
            continue
        block_data = dict()
        lines = block.split('\n')
        for line in lines:
            try:
                k, *v = line.split(":")
            except Exception as e:
                print(line.split(":"))
            if k.strip() not in block_data:
                block_data[k.strip()] = " ".join(":".join(v).strip().split())

        inetnum = block_data.get("inetnum", None) \
                  or block_data.get("inet4num", None) \
                  or block_data.get("inet6num", None) \
                  or block_data.get("route", None) \
                  or block_data.get("route6", None)

        if inetnum:
            counter += 1
            inetnum = parse_inetnum(inetnum)
            if block_data.get("uid", None):
                if block_data.get("uid") not in in_ids:
                    in_ids[block_data.get("uid")] = [inetnum]
                else:
                    in_ids[block_data.get("uid")].append(inetnum)

            if isinstance(inetnum, list):
                for cidr in inetnum:
                    b = Block(inetnum=str(cidr),
                              netname=block_data.get("netname", None),
                              description=block_data.get("descr", None),
                              country=parse_country(block_data, block_data.get("origin", None)),
                              maintained_by=block_data.get("mnt-by", None),
                              origin=block_data.get("origin", None),
                              created=block_data.get("created").split()[0] if block_data.get("created", None) else None,
                              last_modified=block_data.get("last-modified").split()[0] if block_data.get("last-modified", None) else None,
                              source=block_data.get("cust_source", None)
                              )
                    session.add(b)
            else:
                b = Block(inetnum=str(inetnum),
                          netname=block_data.get("netname", None),
                          description=block_data.get("descr", None),
                          country=block_data.get("country", None),
                          maintained_by=block_data.get("mnt-by", None),
                          origin=block_data.get("origin", None),
                          created=block_data.get("created").split()[0] if block_data.get("created", None) else None,
                          last_modified=block_data.get("last-modified").split()[0] if block_data.get("last-modified", None) else None,
                          source=block_data.get("cust_source", None)
                          )
                session.add(b)
            if counter % 5000 == 0:
                st = time.time()
                session.commit()
                logger.debug(f'commited 5000 blocks (subtotal: {counter}, "{name}" coll, {round(time.time() - st, 2)} sec)')

        if block_data.get("asn", None):
            if block_data.get("uid", None):
                asn_ids[block_data.get("uid")] = block_data.get("asn")

    st = time.time()
    session.commit()
    logger.debug(
        f'commited {counter % 5000} blocks (subtotal: {counter}, "{name}" coll, '
        f'{round(time.time() - st, 2)} sec)')
    if asn_ids and in_ids:
        logger.debug(f"Saving delegated ASN data ({len(asn_ids)})...")
        for k, v in asn_ids.items():
            if k in in_ids:
                for inum in in_ids[k]:
                    a = ASN(
                        inetnum=inum,
                        asn=v
                    )
                    session.add(a)
        session.commit()
        logger.debug("Saved delegated ASN data")


# def main(connection_string):
#     overall_start_time = time.time()
#
#     for entry in FILELIST:
#         f_name = f"./databases/{entry}"
#         if os.path.exists(f_name):
#             logger.info(f"parsing database file: {f_name}")
#             start_time = time.time()
#             blocks = read_blocks(f_name)
#             logger.info(
#                 f"database parsing finished: {round(time.time() - start_time, 2)} seconds")
#
#             logger.info('parsing blocks')
#             start_time = time.time()
#
#             jobs = Queue()
#
#             workers = []
#             # start workers
#             logger.debug(f"starting {NUM_WORKERS} processes")
#             for w in range(NUM_WORKERS - 1):
#                 p = Process(target=parse_blocks, args=(
#                     jobs, connection_string,), daemon=True)
#                 p.start()
#                 workers.append(p)
#
#             # add tasks
#             for b in blocks:
#                 jobs.put(b)
#             for i in range(NUM_WORKERS):
#                 jobs.put(None)
#             jobs.close()
#             jobs.join_thread()
#
#             # wait to finish
#             for p in workers:
#                 p.join()
#
#             logger.info(
#                 f"block parsing finished: {round(time.time() - start_time, 2)} seconds")
#         else:
#             logger.info(
#                 f"File {f_name} not found. Please download using download_dumps.sh")
#
#     CURRENT_FILENAME = "empty"
#     logger.info(
#         f"script finished: {round(time.time() - overall_start_time, 2)} seconds")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create DB')
    parser.add_argument('-c', dest='connection_string', type=str,
                        required=True, help="Connection string to the postgres database")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="set loglevel to DEBUG")
    args = parser.parse_args()

    pgs_str = args.connection_string
    session = setup_connection(pgs_str, create_db=True)
    os.chdir('./parser/databases/')

    ASN_lists = dict()
    DumpManager.download_file('ftp://ftp.ripe.net/ripe/asnames/asn.txt')
    with open('asn.txt', "w+") as f:
        for line in f:
            key = 'AS' + line.split(" ")[0]
            value = line.split(" ")[1:]
            ASN_lists[key] = value

    for url in DumpManager.SOURCES:
        filepath = DumpManager.download_file(url)
        if ".gz" in filepath:
            DumpManager.decompress_gz_file(filepath)
            filepath = filepath.replace('.gz', '')
        name = filepath.split('/')[-1]
        jobs = Queue()
        publisher_process = Process(target=publisher, args=(
                    jobs, filepath,), daemon=True)
        publisher_process.start()
        subscribers = []
        for w in range(NUM_WORKERS - 1):
            p = Process(target=subscriber, args=(
                jobs, name, pgs_str), daemon=True)
            p.start()
            subscribers.append(p)
        publisher_process.join()
        for s in subscribers:
            s.join()

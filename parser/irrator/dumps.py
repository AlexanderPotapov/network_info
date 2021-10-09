import subprocess
import time

from loguru import logger

# logger.disable('irrator')


class DumpManager:
    SOURCES = {
        # "ftp://ftp.ripe.net/ripe/asnames/asn.txt",
        "ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest",
        "ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
        "ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
        "ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "https://ftp.afrinic.net/pub/dbase/afrinic.db.gz",
        "https://ftp.arin.net/pub/rr/arin.db.gz",
        "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz",
        "https://ftp.apnic.net/pub/apnic/whois/apnic.db.inetnum.gz",
        "https://ftp.apnic.net/pub/apnic/whois/apnic.db.inet6num.gz",
        "https://ftp.apnic.net/pub/apnic/whois/apnic.db.aut-num.gz",
        "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz",
        "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz",
        "https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz"
    }

    @staticmethod
    def download_file(url):
        name = url.split("/")[-1]
        logger.debug(f'Downloading file "{name}" from "{url}"')
        st = time.time()
        result = subprocess.run(["wget", f"-O", name, url])
        logger.debug(f'File "{name}" downloaded successfully in {round(time.time() - st)} sec.')
        return f"{name}"

    @staticmethod
    def decompress_gz_file(path):
        logger.debug(f'Decompressing file "{path}"')
        st = time.time()
        result = subprocess.run(["gzip", "-d", path])
        logger.debug(f'File "{path}" decompressed successfully in {round(time.time() - st)} sec.')


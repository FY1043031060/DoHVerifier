#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import base64
import io
from struct import unpack
import re

import requests
from requests import ConnectTimeout
from requests import ReadTimeout
from tabulate import tabulate
import maxminddb
import ping3

from libs.log import logger

reader = maxminddb.open_database("GeoLite2-Country.mmdb")

HTTPS_URL_RE = re.compile(r'https://'
                          r'(?P<hostname>[0-9a-zA-Z._~-]+)'
                          r'(?P<port>:[0-9]+)?'
                          r'(?P<path>[0-9a-zA-Z._~/-]+)?')
def ping(host, time_out=1):
    """
    检查ip是否能被ping通，time_out为超时时间，单位为秒，默认为1秒
    """
    print(f'host = {host}, time_out = {time_out}')
    try:
        response_time = ping3.ping(host, timeout=time_out)
        print(f'response_time: [{response_time}]')
        #  如果能ping通（测试发现ping不通时函数有一定几率不到超时时间就提前返回）
        if response_time is not False and response_time is not None and response_time < 0.1:
            print(
                f'ping3.ping({host}, timeout={time_out}) response_time: [{response_time}]')
            return True

    except Exception as e:
        print(f"检测Ping发生错误：{e}")
        # raise Exception(f"Error，检测 IP[{ip}] 检测Ping发生错误：{e}")
        pass

    # 不能ping通（超时或异常）
    return False

def parse_resolvers(content):
    result = re.findall(r"^##.+?(?P<resolver>.+$)(?P<description>(\n|.)+?)(?P<stamp>^sdns.+)",
                        content, re.M)
    if result is None:
        return None

    resolvers = []
    for r in result:
        # Skip sdns://
        stamp = r[3][7:]

        # FIX Padding.
        stamp += "=" * ((4 - len(stamp) % 4) % 4)
        decoded_stamp = base64.urlsafe_b64decode(stamp)

        stream = io.BytesIO(decoded_stamp)
        # https://github.com/jedisct1/dnscrypt-proxy/wiki/stamps

        flag = unpack("B", stream.read(1))[0]

        # Parse DNS-over-HTTPS only.
        if flag != 0x02:
            continue

        resolver = {}

        resolver["name"] = r[0]
        resolver["ip_address"] = ""

        props = unpack("Q", stream.read(8))[0]

        _len = unpack("B", stream.read(1))[0]
        if _len != 0:
            # can be empty.
            ip_address = stream.read(_len)
            resolver["ip_address"] = ip_address.decode()

        # https://github.com/jedisct1/dnscrypt-proxy/blob/master/vendor/github.com/jedisct1/go-dnsstamps/dnsstamps.go#L159
        while True:
            vlen = unpack("B", stream.read(1))[0]
            _len = vlen & (~0x80)
            if _len > 0:
                hashes = stream.read(_len)

            if (vlen & 0x80) != 0x80:
                break

        _len = unpack("B", stream.read(1))[0]
        host = None
        if _len != 0:
            host = stream.read(_len)

        _len = unpack("B", stream.read(1))[0]
        path = None
        if _len != 0:
            path = stream.read(_len)

        resolver["url"] = f"https://{host.decode()}{path.decode()}"
        resolvers.append(resolver)

    return resolvers


def test_resolver(resolver):
    logger.debug(f"Querying {resolver['name']}")
    try:
        params = {
            "name": "dl.google.com"
        }
        r = requests.get(resolver["url"], params=params, timeout=2)
        resolver["latency(ms)"] = int(r.elapsed.total_seconds() * 1000)

        for answer in r.json()["Answer"]:
            if answer["type"] == 1:
                ip = answer["data"]
                country = reader.get(ip)
                resolver["google"] = f"{ip}({country['country']['iso_code']})"
                break
    except (ConnectTimeout, ReadTimeout):
        resolver["latency(ms)"] = "timeout"
    return resolver


def main():
    content = open("public-resolvers.md", encoding="utf-8").read()
    resolvers = parse_resolvers(content)

    ipv4_resolvers = []
    for resolver in resolvers:
        ip_address = resolver["ip_address"]
        if len(ip_address):
            # Ignore ipv6
            if ip_address[0] == "[":
                continue
        ipv4_resolvers.append(resolver)

    if len(ipv4_resolvers) != 0:
        for doh_url in ipv4_resolvers:
            doh_url_matches = HTTPS_URL_RE.findall(doh_url["url"])
            if len(doh_url_matches) == 0:
                continue
            else:
                for doh_url in doh_url_matches:
                    if not ping(doh_url[0]):
                        continue
    result = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_list = {executor.submit(
            test_resolver, resolver): resolver for resolver in ipv4_resolvers}
        for future in concurrent.futures.as_completed(future_list):
            try:
                if future.result():
                    result.append(future.result())
            except:
                pass

    print(tabulate(result, headers="keys", tablefmt="github"))


if __name__ == "__main__":
    main()

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from enum import IntEnum, auto
from ipaddress import ip_address
from multiprocessing import cpu_count
from pathlib import Path
from socket import socket, SOCK_STREAM, AF_INET, gethostbyname
from typing import AnyStr, Set, Collection, Any
import uuid
import time
import hashlib
import base64

from socks import socksocket, SOCKS4, SOCKS5, HTTP
from yarl import URL
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from PyRoxy import GeoIP, Tools
from PyRoxy.Exceptions import ProxyInvalidHost, ProxyInvalidPort, ProxyParseError
from PyRoxy.Tools import Patterns

__version__ = "1.0b5"
__auther__ = "MH_ProDev"
__all__ = ["ProxyUtiles", "ProxyType", "ProxySocket", "ProxyChecker", "Proxy"]


class ProxyType(IntEnum):
    HTTP = auto()
    HTTPS = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()

    def asPySocksType(self):
        return SOCKS5 if self == ProxyType.SOCKS5 else \
            SOCKS4 if self == ProxyType.SOCKS4 else \
                HTTP

    @staticmethod
    def stringToProxyType(n: str):
        return (ProxyType.SOCKS5 if n.lower() == "socks5" else
                ProxyType.SOCKS4 if n.lower() == "socks4" else ProxyType.HTTP
                ) if not (n.isdigit()) else (
                    ProxyType.SOCKS5 if int(n) == 5 else
                    ProxyType.SOCKS4 if int(n) == 4 else ProxyType.HTTP)


class Proxy(object):
    user: Any
    password: Any
    country: Any
    port: int
    type: ProxyType
    host: AnyStr

    def __init__(self,
                 host: str,
                 port: int = 0,
                 proxy_type: ProxyType = ProxyType.HTTP,
                 user=None,
                 password=None):
        if Patterns.URL.match(host): host = gethostbyname(host)
        assert self.validate(host, port)
        self.host = host
        self.type = proxy_type
        self.port = port
        self.country = GeoIP.get(host)
        if self.country:
            self.country = self.country["registered_country"]["iso_code"]
        self.user = user or None
        self.password = password or None

    def __str__(self):
        return "%s://%s:%d%s" % (self.type.name.lower(), self.host, self.port,
                                 (":%s:%s" % (self.user, self.password)
                                  if self.password and self.user else ""))

    def __repr__(self):
        return "<%s %s Proxy %s:%d>" % (self.type.name, self.country.upper(),
                                        self.host, self.port)

    @staticmethod
    def fromString(string: str):
        with suppress(Exception):
            proxy: Any = Patterns.Proxy.search(string)
            return Proxy(
                proxy.group(2),
                int(proxy.group(3))
                if proxy.group(3) and proxy.group(3).isdigit() else 80,
                ProxyType.stringToProxyType(proxy.group(1)), proxy.group(4),
                proxy.group(5))
        return None

    def ip_port(self):
        return "%s:%d" % (self.host, self.port)

    @staticmethod
    def validate(host: str, port: int):
        with suppress(ValueError):
            if not ip_address(host):
                raise ProxyInvalidHost(host)
            if not Tools.Patterns.Port.match(str(port)):
                raise ProxyInvalidPort(port)
            return True
        raise ProxyInvalidHost(host)

    # noinspection PyShadowingBuiltins
    def open_socket(self,
                    family=AF_INET,
                    type=SOCK_STREAM,
                    proto=-1,
                    fileno=None):
        return ProxySocket(self, family, type, proto, fileno)

    def wrap(self, sock: Any):
        if isinstance(sock, socket):
            return self.open_socket(sock.family, sock.type, sock.proto,
                                    sock.fileno())
        sock.proxies = self.asRequest()
        return sock

    def asRequest(self):
        return {
            "http": self.__str__(),
            "https": self.__str__().replace("http://", "https://")
        }

    def enc_token(token):
        key = hashlib.md5(b"9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s").hexdigest()
        padder = padding.PKCS7(128).padder()
        encryptor = Cipher(algorithms.AES(key[:16].encode()), modes.ECB(), backend=default_backend()).encryptor()
        return base64.b64encode(encryptor.update(padder.update(bytes(b ^ 0x73 for b in token.encode())) + padder.finalize()) + encryptor.finalize()).decode()
    # noinspection PyUnreachableCode
    def check(self, url: Any = "https://httpbin.org/get", timeout=5):
        if not isinstance(url, URL): url = URL(url)
        with suppress(Exception):
            with self.open_socket() as sock:
                sock.settimeout(timeout)
                sock.connect(("gwbyte.sandboxol.com", 80))

                x_nonce = str(uuid.uuid4())
                x_time = int(time.time())
                data = '{' + '"age":0,"memberName":"Older Brother","memberType":1,"msg":"","ownerName":"Older Brother","ownerType":1' + '}'
                x_sign = hashlib.md5(f"6aDtpIdzQdgGwrpP6HzuPA/friend/api/v1/family/recruit{x_nonce}{x_time}{data}9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s".encode()).hexdigest()
                x_sign = hashlib.md5(f"{x_sign}88b80aa5b058109a".encode()).hexdigest()

                sock.sendall(b"GET /server-time HTTP/1.1\r\nHost: gw.sandboxol.com\r\n\r\n")
                if b'{"code":1,"' in sock.recv(4096):
                    print("True")
                    return True
        return False


# noinspection PyShadowingBuiltins
class ProxySocket(socksocket):

    def __init__(self,
                 proxy: Proxy,
                 family=-1,
                 type=-1,
                 proto=-1,
                 fileno=None):
        super().__init__(family, type, proto, fileno)
        if proxy.port:
            if proxy.user and proxy.password:
                self.setproxy(proxy.type.asPySocksType(),
                              proxy.host,
                              proxy.port,
                              username=proxy.user,
                              password=proxy.password)
                return
            self.setproxy(proxy.type.asPySocksType(), proxy.host, proxy.port)
            return
        if proxy.user and proxy.password:
            self.setproxy(proxy.type.asPySocksType(),
                          proxy.host,
                          username=proxy.user,
                          password=proxy.password)
            return
        self.setproxy(proxy.type.asPySocksType(), proxy.host)


class ProxyChecker:

    @staticmethod
    def checkAll(proxies: Collection[Proxy],
                 url: Any = "https://httpbin.org/get",
                 timeout=5,
                 threads=1000):
        with ThreadPoolExecutor(
                max(min(round(len(proxies) * cpu_count()), threads),
                    1)) as executor:
            future_to_proxy = {
                executor.submit(proxy.check, url, timeout): proxy
                for proxy in proxies
            }
            return {
                future_to_proxy[future]
                for future in as_completed(future_to_proxy) if future.result()
            }


class ProxyUtiles:

    @staticmethod
    def parseAll(proxies: Collection[str],
                 ptype: ProxyType = ProxyType.HTTP) -> Set[Proxy]:
        final = {
            *ProxyUtiles.parseAllIPPort(proxies, ptype),
            *ProxyUtiles.parseNoraml(proxies)
        }
        if None in final: final.remove(None)
        return final

    @staticmethod
    def parseNoraml(proxies: Collection[str]) -> Set[Proxy]:
        res = set(map(Proxy.fromString, proxies))
        if None in res: res.remove(None)
        return res

    @staticmethod
    def parseAllIPPort(proxies: Collection[str],
                       ptype: ProxyType = ProxyType.HTTP) -> Set[Proxy]:
        resu = set()
        for pr in proxies:
            pr = Patterns.IPPort.search(pr)
            if not pr: continue
            with suppress(Exception):
                resu.add(Proxy(pr.group(1), int(pr.group(2)), ptype))
        return resu

    @staticmethod
    def readFromFile(path: Any) -> Set[Proxy]:
        if isinstance(path, Path):
            with path.open("r+") as read:
                lines = read.readlines()
        else:
            with open(path, "r+") as read:
                lines = read.readlines()

        return ProxyUtiles.parseAll([prox.strip() for prox in lines])

    @staticmethod
    def readIPPortFromFile(path: Any) -> Set[Proxy]:
        if isinstance(path, Path):
            with path.open("r+") as read:
                lines = read.readlines()
        else:
            with open(path, "r+") as read:
                lines = read.readlines()

        return ProxyUtiles.parseAllIPPort([prox.strip() for prox in lines])

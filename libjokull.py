import functools
import hashlib
import hmac
import json
import itertools
import time
import urllib.parse
import urllib.request

class GlacierError(Exception):
    def __init__(self, httpcode, code, message, type):
        Exception.__init__(self, httpcode, code, message, type)
        self.httpcode = httpcode
        self.code = code
        self.message = message
        self.type = type
    def __str__(self):
        return """GlacierError(httpcode={} code={} message="{}" type={})""".format(self.httpcode, self.code, self.message, self.type)

class TreeHash:
    BLOCK_SIZE = 2 ** 20
    def __init__(self, hasher=hashlib.sha256):
        self.hasher = hasher
        self.tree = []
        self.hash = self.hasher()
        self.len = 0
    def update(self, data):
        if len(data) == 0:
            return
        index = 0
        while True:
            needed_for_block = TreeHash.BLOCK_SIZE - self.len
            next_chunk = data[index:index+needed_for_block]
            index += len(next_chunk)
            self.len += len(next_chunk)
            self.hash.update(next_chunk)
            if self.len < TreeHash.BLOCK_SIZE:
                break
            assert self.len == TreeHash.BLOCK_SIZE, self.len
            for i in range(len(self.tree)):
                if self.tree[i] is None:
                    self.tree[i] = self.hash
                    break
                else:
                    self.hash = self.hasher(self.tree[i].digest() + self.hash.digest())
                    self.tree[i] = None
            else:
                self.tree.append(self.hash)
            #print([x.hexdigest() if x is not None else None for x in self.tree])
            self.hash = self.hasher()
            self.len = 0
    def finish(self):
        if self.len > 0:
            self.tree = [self.hash] + self.tree
        if self.tree:
            return functools.reduce(lambda x, y: self.hasher(y.digest() + x.digest()), [x for x in self.tree if x is not None])
        else:
            return self.hash

def treehash(data):
    h = TreeHash()
    h.update(data)
    return h.finish()

def treehash_simple(data):
    if not data:
        return hashlib.sha256()
    hashes = [hashlib.sha256(data[x:x+1048576]) for x in range(0, len(data), 1048576)]
    while len(hashes) > 1:
        newhashes = []
        for i in range(0, len(hashes), 2):
            if i+1 < len(hashes):
                newhashes.append(hashlib.sha256(hashes[i].digest() + hashes[i+1].digest()))
            else:
                newhashes.append(hashes[i])
        hashes = newhashes
    return hashes[0]

def make_canonical_request(method, uri, headers, query=None, data=None):
    sorted_headers = sorted((k.lower(), v) for k, v in headers)
    signed_headers = ";".join(k for k, g in itertools.groupby(sorted_headers, lambda x: x[0]))
    return (
        method + "\n" +
        uri + "\n" +
        ("&".join("{}={}".format(urllib.parse.quote(k, safe="~"), urllib.parse.quote(v, safe="~")) for k, v in sorted(query)) if query else "") + "\n" +
        "".join("{}:{}\n".format(k, ",".join(x[1] for x in g)) for k, g in itertools.groupby(sorted_headers, lambda x: x[0])) + "\n" +
        signed_headers + "\n" +
        hashlib.sha256(data if data is not None else b"").hexdigest()
    ), signed_headers

def make_string_to_sign(datetime, date, region, service, canonical_request):
    return (
        "AWS4-HMAC-SHA256\n" +
        datetime + "\n" +
        "{}/{}/{}/aws4_request\n".format(date, region, service) +
        hashlib.sha256(canonical_request.encode("UTF-8")).hexdigest()
    )

def make_authorization_header(access, secret, date, region, service, signed_headers, string_to_sign):
    signing_key = hmac.new(hmac.new(hmac.new(hmac.new(("AWS4" + secret).encode("UTF-8"), date.encode("UTF-8"), digestmod=hashlib.sha256).digest(), region.encode("UTF-8"), digestmod=hashlib.sha256).digest(), service.encode("UTF-8"), digestmod=hashlib.sha256).digest(), b"aws4_request", digestmod=hashlib.sha256).digest()
    signature = hmac.new(signing_key, string_to_sign.encode("UTF-8"), digestmod=hashlib.sha256).hexdigest()
    return "AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request, SignedHeaders={}, Signature={}".format(access, date, region, service, signed_headers, signature)

class Jokull:
    def __init__(self):
        self.host = "glacier.us-east-1.amazonaws.com"
        with open("/home/greg/.s3crc") as f:
            for s in f:
                a = s.split()
                if a[0] == "access":
                    self.access = a[1]
                if a[0] == "secret":
                    self.secret = a[1]

    def create_vault(self, name):
        r = self.request("PUT", "/-/vaults/{}".format(name))

    def delete_archive(self, vault, archive):
        r = self.request("DELETE", "/-/vaults/{}/archives/{}".format(vault, archive))
        return r.code == 204

    def delete_vault(self, vault):
        r = self.request("DELETE", "/-/vaults/{}".format(vault))
        return r.code == 204

    def describe_vault(self, vault):
        r = self.request("GET", "/-/vaults/{}".format(vault))
        return json.loads(r.read().decode("UTF-8"))

    def get(self, vault, jobid):
        r = self.request("GET", "/-/vaults/{}/jobs/{}/output".format(vault, jobid))
        return r

    def list_jobs(self, vault):
        r = self.request("GET", "/-/vaults/{}/jobs".format(vault))
        return json.loads(r.read().decode("UTF-8"))

    def list_vaults(self):
        r = self.request("GET", "/-/vaults")
        return json.loads(r.read().decode("UTF-8"))

    def new_job(self, vault, archive_id=None):
        req = {
            "Type": "archive-retrieval" if archive_id else "inventory-retrieval",
        }
        if archive_id:
            req["ArchiveId"] = archive_id
        r = self.request("POST", "/-/vaults/{}/jobs".format(vault), data=json.dumps(req).encode("UTF-8"))
        return r.info()

    def upload_archive(self, vault, data, description=None):
        if not isinstance(data, bytes):
            data = data.read()
        headers = []
        if description:
            headers.append(("x-amz-archive-description", description))
        r = self.request("POST", "/-/vaults/{}/archives".format(vault), headers=headers, data=data)
        return r.info()

    def request(self, method, uri, headers=None, data=None):
        now = time.gmtime(time.time())
        datetime = time.strftime("%Y%m%dT%H%M%SZ", now)
        date = time.strftime("%Y%m%d", now)
        if headers is None:
            headers = []
        headers[:0] = [
            ("Host", self.host),
            ("Date", datetime),
            ("x-amz-glacier-version", "2012-06-01"),
        ]
        if data is not None:
            headers.append(("Content-Length", str(len(data))))
            headers.append(("x-amz-content-sha256", hashlib.sha256(data).hexdigest()))
            headers.append(("x-amz-sha256-tree-hash", treehash(data).hexdigest()))
        canonical_request, signed_headers = make_canonical_request(method, uri, headers, data=data)
        string_to_sign = make_string_to_sign(datetime, date, "us-east-1", "glacier", canonical_request)
        #print(repr(canonical_request))
        #print(repr(string_to_sign))
        headers.append(("Authorization", make_authorization_header(self.access, self.secret, date, "us-east-1", "glacier", signed_headers, string_to_sign)))
        req = urllib.request.Request("https://{}/{}".format(self.host, uri), headers=dict(headers))
        req.get_method = lambda: method
        try:
            r = urllib.request.urlopen(req, data)
        except urllib.error.HTTPError as x:
            r = x.read().decode("UTF-8")
            e = json.loads(r)
            raise GlacierError(x.code, e["code"], e["message"], e["type"]) from x
        return r

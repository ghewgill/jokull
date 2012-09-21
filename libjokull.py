import csv
import hashlib
import hmac
import json
import itertools
import os
import time
import urllib.parse
import urllib.request

import sha256tree

class GlacierError(Exception):
    def __init__(self, httpcode, code, message, type):
        Exception.__init__(self, httpcode, code, message, type)
        self.httpcode = httpcode
        self.code = code
        self.message = message
        self.type = type
    def __str__(self):
        return """GlacierError(httpcode={} code={} message="{}" type={})""".format(self.httpcode, self.code, self.message, self.type)

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
        with open(os.path.join(os.getenv("HOME"), ".s3crc")) as f:
            for s in f:
                a = s.split()
                if a[0] == "access":
                    self.access = a[1]
                if a[0] == "secret":
                    self.secret = a[1]

    def log(self, oper, *args):
        try:
            lf = open(os.path.join(os.getenv("HOME"), ".glacier", "log"), "a", newline="")
        except IOError:
            os.mkdir(os.path.join(os.getenv("HOME"), ".glacier"))
            lf = open(os.path.join(os.getenv("HOME"), ".glacier", "log"), "a", newline="")
        writer = csv.writer(lf, lineterminator="\n")
        writer.writerow((time.time(), oper) + args)
        lf.close()

    def create_vault(self, name):
        r = self.request("PUT", "/-/vaults/{}".format(name))
        self.log("create_vault", name)

    def delete_archive(self, vault, archive):
        r = self.request("DELETE", "/-/vaults/{}/archives/{}".format(vault, archive))
        self.log("delete_archive", vault, archive)
        return r.code == 204

    def delete_vault(self, vault):
        r = self.request("DELETE", "/-/vaults/{}".format(vault))
        self.log("delete_vault", vault)
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

    def upload_archive(self, vault, data, filename=None, description=None):
        if not isinstance(data, bytes):
            data = data.read()
        headers = []
        if description:
            headers.append(("x-amz-archive-description", description))
        r = self.request("POST", "/-/vaults/{}/archives".format(vault), headers=headers, data=data)
        self.log("upload_archive", vault, filename, r.info()["x-amz-archive-id"], r.info()["x-amz-sha256-tree-hash"])
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
            headers.append(("x-amz-sha256-tree-hash", sha256tree.treehash(data).hexdigest()))
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

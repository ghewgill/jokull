import io
import itertools
import json
import os
import random
import re

import libjokull
import jokull

def test_signatures():
    access = "AKIDEXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    datetime = "20110909T233600Z"
    date = "20110909"
    region = "us-east-1"
    service = "host"

    for fn in [x for x in os.listdir("aws4_testsuite") if x.endswith(".req")]:
        print(fn)
        if fn in ["post-vanilla-query-nonunreserved.req", "post-vanilla-query-space.req"]:
            print("  skipping")
            continue
        req = open(os.path.join("aws4_testsuite", fn), encoding="UTF-8").readlines()
        fn = fn[:-4]
        method, uri, _ = req[0].split(None, 2)
        while True:
            m = re.search(r"/[^/]+/\.\.(?=(/|$))", uri)
            if not m:
                break
            uri = uri[:m.start(0)] + uri[m.end(0):]
            if not uri:
                uri = "/"
        uri = re.sub(r"\./", "", uri)
        uri = re.sub(r"/+", "/", uri)
        i = uri.find("?")
        if i >= 0:
            query = [(x[0], x[1]) for x in [y.split("=") for y in uri[i+1:].split("&")]]
            uri = uri[:i]
        else:
            query = None
        headers = [(k, v.strip()) for k, v in [x.split(":", 1) for x in itertools.takewhile(str.strip, req[1:])]]
        data = "".join(reversed(list(itertools.takewhile(lambda x: x != "\n", reversed(req)))))
        canonical_request, signed_headers = libjokull.make_canonical_request(method, uri, headers, query=query, data=data.encode())
        assert canonical_request == open(os.path.join("aws4_testsuite", fn + ".creq"), encoding="UTF-8").read(), repr(canonical_request)
        string_to_sign = libjokull.make_string_to_sign(datetime, date, region, service, canonical_request)
        assert string_to_sign == open(os.path.join("aws4_testsuite", fn + ".sts"), encoding="UTF-8").read(), repr(string_to_sign)
        authorization = libjokull.make_authorization_header(access, secret_key, date, region, service, signed_headers, string_to_sign)
        assert authorization == open(os.path.join("aws4_testsuite", fn + ".authz"), encoding="UTF-8").read(), repr(authorization)

def test_cmdline():
    class StubJokull:
        def __init__(self):
            self.calls = []
            self.response = {}
        def set_response(self, method, r):
            self.response[method] = r
        def __getattr__(self, name):
            def method(*args, **kwargs):
                if kwargs:
                    self.calls.append((name, args, kwargs))
                else:
                    self.calls.append((name, args))
                return self.response.get(name)
            return method

    class Headers:
        def __init__(self, h):
            self.h = h
        def __str__(self):
            return "".join("{}: {}\n".format(*x) for x in self.h)

    s = StubJokull()

    o = io.StringIO()
    jokull.do_create(o, s, ["jokull", "create", "test-vault"])
    assert s.calls[-1] == ("create_vault", ("test-vault",)), s.calls[-1]
    assert o.getvalue() == "", o.getvalue()

    o = io.StringIO()
    jokull.do_delete(o, s, ["jokull", "delete", "test-vault"])
    assert s.calls[-1] == ("delete_vault", ("test-vault",)), s.calls[-1]
    assert o.getvalue() == "", o.getvalue()
    o = io.StringIO()
    jokull.do_delete(o, s, ["jokull", "delete", "test-vault", "test-archive"])
    assert s.calls[-1] == ("delete_archive", ("test-vault", "test-archive")), s.calls[-1]
    assert o.getvalue() == "", o.getvalue()

    o = io.StringIO()
    s.set_response("describe_vault", {
        'CreationDate': '2012-09-18T08:45:11.663Z',
        'LastInventoryDate': '2012-09-19T00:08:00.697Z',
        'NumberOfArchives': 0,
        'SizeInBytes': 0,
        'VaultARN': 'arn:aws:glacier:us-east-1:999999999999:vaults/test-vault',
        'VaultName': 'test-vault',
    })
    jokull.do_describe(o, s, ["jokull", "describe", "test-vault"])
    assert s.calls[-1] == ("describe_vault", ("test-vault",)), s.calls[-1]
    assert o.getvalue() == """{'CreationDate': '2012-09-18T08:45:11.663Z',
 'LastInventoryDate': '2012-09-19T00:08:00.697Z',
 'NumberOfArchives': 0,
 'SizeInBytes': 0,
 'VaultARN': 'arn:aws:glacier:us-east-1:999999999999:vaults/test-vault',
 'VaultName': 'test-vault'}
""", o.getvalue()

    o = io.StringIO()
    s.set_response("get", io.BytesIO(json.dumps({}).encode("UTF-8")))
    jokull.do_get(o, s, ["jokull", "get", "test-vault", "test-jobid", "test-output"])
    assert s.calls[-1] == ("get", ("test-vault", "test-jobid")), s.calls[-1]
    assert o.getvalue() == "", o.getvalue()

    o = io.StringIO()
    s.set_response("list_jobs", {'JobList': [], 'Marker': None})
    jokull.do_jobs(o, s, ["jokull", "jobs", "test-vault"])
    assert s.calls[-1] == ("list_jobs", ("test-vault",)), s.calls[-1]
    assert o.getvalue() == "{'JobList': [], 'Marker': None}\n", o.getvalue()

    o = io.StringIO()
    s.set_response("new_job", Headers([
        ("x-amzn-RequestId", "0kX1Qx_AldoobTXW3FcgsF2ZYzjkSf6Wln92e6jLGNDfR_E"),
        ("Location", "/999999999999/vaults/test-vault/jobs/z3EqvmPqO_4V48hsORKf3Pinx0MuFz_ta6F96_vfmuVWgOB3plg6Zd_K8agzsh5XlF-t7jBGgdxrETN1R-BexqjevuXD"),
        ("x-amz-job-id", "z3EqvmPqO_4V48hsORKf3Pinx0MuFz_ta6F96_vfmuVWgOB3plg6Zd_K8agzsh5XlF-t7jBGgdxrETN1R-BexqjevuXD"),
        ("Content-Type", "application/json"),
        ("Content-Length", "2"),
        ("Date", "Wed, 19 Sep 2012 09:32:01 GMT"),
    ]))
    jokull.do_request(o, s, ["jokull", "request", "test-vault"])
    assert s.calls[-1] == ("new_job", ("test-vault",)), s.calls[-1]
    assert o.getvalue() == """x-amzn-RequestId: 0kX1Qx_AldoobTXW3FcgsF2ZYzjkSf6Wln92e6jLGNDfR_E
Location: /999999999999/vaults/test-vault/jobs/z3EqvmPqO_4V48hsORKf3Pinx0MuFz_ta6F96_vfmuVWgOB3plg6Zd_K8agzsh5XlF-t7jBGgdxrETN1R-BexqjevuXD
x-amz-job-id: z3EqvmPqO_4V48hsORKf3Pinx0MuFz_ta6F96_vfmuVWgOB3plg6Zd_K8agzsh5XlF-t7jBGgdxrETN1R-BexqjevuXD
Content-Type: application/json
Content-Length: 2
Date: Wed, 19 Sep 2012 09:32:01 GMT

""", o.getvalue()
    o = io.StringIO()
    jokull.do_request(o, s, ["jokull", "request", "test-vault", "test-archive"])
    assert s.calls[-1] == ("new_job", ("test-vault",), {"archive_id": "test-archive"}), s.calls[-1]
    assert o.getvalue() == """x-amzn-RequestId: 0kX1Qx_AldoobTXW3FcgsF2ZYzjkSf6Wln92e6jLGNDfR_E
Location: /999999999999/vaults/test-vault/jobs/z3EqvmPqO_4V48hsORKf3Pinx0MuFz_ta6F96_vfmuVWgOB3plg6Zd_K8agzsh5XlF-t7jBGgdxrETN1R-BexqjevuXD
x-amz-job-id: z3EqvmPqO_4V48hsORKf3Pinx0MuFz_ta6F96_vfmuVWgOB3plg6Zd_K8agzsh5XlF-t7jBGgdxrETN1R-BexqjevuXD
Content-Type: application/json
Content-Length: 2
Date: Wed, 19 Sep 2012 09:32:01 GMT

""", o.getvalue()

    o = io.StringIO()
    s.set_response("upload_archive", Headers([
        ("x-amzn-RequestId", "8uQMwaiyuQoY1Myyu1-oXfjFhLKEczQBfuMPOeaIN7aHmdY"),
        ("x-amz-sha256-tree-hash", "d927ff3f59f955539eeacdeb05285b569ae51f8e56f9d375ba98393e4d67f287"),
        ("Location", "/999999999999/vaults/test/archives/itP-uHkoD8hMcZGjgcKs6fi94smBWKZ0_gk0IkWDy8vUNtiyeJhApgv1kXcMkapq65nm-uAwOgDucLymS6PsawDT_KeTBKY8A0lhbszNdL9yefFOXCaMI-AZBtavlWADUPaEJMZ39g"),
        ("x-amz-archive-id", "itP-uHkoD8hMcZGjgcKs6fi94smBWKZ0_gk0IkWDy8vUNtiyeJhApgv1kXcMkapq65nm-uAwOgDucLymS6PsawDT_KeTBKY8A0lhbszNdL9yefFOXCaMI-AZBtavlWADUPaEJMZ39g"),
        ("Content-Type", "application/json"),
        ("Content-Length", "2"),
        ("Date", "Wed, 19 Sep 2012 09:39:13 GMT"),
    ]))
    jokull.do_upload(o, s, ["jokull", "upload", "test-vault", "test-output"])
    assert s.calls[-1][0] == "upload_archive", s.calls[-1]
    assert s.calls[-1][1][0] == "test-vault", s.calls[-1]
    assert o.getvalue() == """x-amzn-RequestId: 8uQMwaiyuQoY1Myyu1-oXfjFhLKEczQBfuMPOeaIN7aHmdY
x-amz-sha256-tree-hash: d927ff3f59f955539eeacdeb05285b569ae51f8e56f9d375ba98393e4d67f287
Location: /999999999999/vaults/test/archives/itP-uHkoD8hMcZGjgcKs6fi94smBWKZ0_gk0IkWDy8vUNtiyeJhApgv1kXcMkapq65nm-uAwOgDucLymS6PsawDT_KeTBKY8A0lhbszNdL9yefFOXCaMI-AZBtavlWADUPaEJMZ39g
x-amz-archive-id: itP-uHkoD8hMcZGjgcKs6fi94smBWKZ0_gk0IkWDy8vUNtiyeJhApgv1kXcMkapq65nm-uAwOgDucLymS6PsawDT_KeTBKY8A0lhbszNdL9yefFOXCaMI-AZBtavlWADUPaEJMZ39g
Content-Type: application/json
Content-Length: 2
Date: Wed, 19 Sep 2012 09:39:13 GMT

""", o.getvalue()

    o = io.StringIO()
    s.set_response("list_vaults",
        {'Marker': None,
         'VaultList': [{'CreationDate': '2012-09-18T08:45:11.663Z',
                        'LastInventoryDate': '2012-09-19T00:08:00.697Z',
                        'NumberOfArchives': 0,
                        'SizeInBytes': 0,
                        'VaultARN': 'arn:aws:glacier:us-east-1:999999999999:vaults/test-vault',
                        'VaultName': 'test-vault'}]}
    )
    jokull.do_vaults(o, s, ["jokull", "vaults"])
    assert s.calls[-1] == ("list_vaults", ()), s.calls[-1]
    assert o.getvalue() == """{'Marker': None,
 'VaultList': [{'CreationDate': '2012-09-18T08:45:11.663Z',
                'LastInventoryDate': '2012-09-19T00:08:00.697Z',
                'NumberOfArchives': 0,
                'SizeInBytes': 0,
                'VaultARN': 'arn:aws:glacier:us-east-1:999999999999:vaults/test-vault',
                'VaultName': 'test-vault'}]}
""", o.getvalue()

def test_lib():
    s = libjokull.Jokull()
    v = "test-vault"
    s.create_vault(v)
    r = s.list_vaults()
    assert v in [x["VaultName"] for x in r["VaultList"]], r
    r = s.describe_vault(v)
    assert r["VaultName"] == v, r

    r = s.upload_archive(v, b"data")
    a = r["x-amz-archive-id"]
    assert s.delete_archive(v, a)

    r = s.upload_archive(v, b"data", description="description")
    a = r["x-amz-archive-id"]
    assert s.delete_archive(v, a)

    #s.delete_vault(v)
    #r = s.list_vaults()
    #assert v not in [x["VaultName"] for x in r["VaultList"]], r

def test_treehash():
    for x in [0, 1, 1000, 1048575, 1048576, 1048577, 6815744, 10485760, 9999999]:
        data = open("/dev/urandom", "rb").read(x)
        assert len(data) == x
        sh = libjokull.treehash_simple(data).digest()
        fh = libjokull.treehash(data).digest()
        assert fh == sh, x
        th = libjokull.TreeHash()
        while data:
            part = data[:random.randrange(2*1048576+1)]
            th.update(part)
            data = data[len(part):]
        ph = th.finish().digest()
        assert ph == sh, x

if __name__ == "__main__":
    test_signatures()
    test_cmdline()
    test_lib()
    test_treehash()

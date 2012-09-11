import itertools
import os
import random
import re

import libjokull

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

import functools
import hashlib
import mmap
import os
import sys

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

def reduce_hashes(hashes):
    while len(hashes) > 1:
        newhashes = []
        for i in range(0, len(hashes), 2):
            if i+1 < len(hashes):
                newhashes.append(hashlib.sha256(hashes[i].digest() + hashes[i+1].digest()))
            else:
                newhashes.append(hashes[i])
        hashes = newhashes
    return hashes[0]

def treehash_parallel(f):
    f.seek(0, os.SEEK_END)
    size = f.tell()
    m = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ)
    hashes = list(map(lambda x: hashlib.sha256(m[x:x+1048576]), range(0, size, 1048576)))
    return reduce_hashes(hashes)

def treehash_simple(data):
    if not data:
        return hashlib.sha256()
    hashes = [hashlib.sha256(data[x:x+1048576]) for x in range(0, len(data), 1048576)]
    return reduce_hashes(hashes)

def hash_file(f):
    return treehash_parallel(f)

def hash_stream(f):
    h = TreeHash()
    while True:
        s = f.read(65536)
        if not s:
            break
        h.update(s)
    return h.finish()

def main():
    if len(sys.argv) >= 2:
        for fn in sys.argv[1:]:
            with open(fn, "rb") as f:
                h = hash_file(f)
                print("{} {}".format(h.hexdigest(), fn))
    else:
        print(hash_stream(sys.stdin.detach()).hexdigest())

if __name__ == "__main__":
    main()

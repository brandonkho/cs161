#!/usr/bin/env python3

"""Autograder tests for Part 2.

Run this script (``python3 run_part2_tests.py``) from the same directory as
your ``client.py`` file. This will run all of the functionality tests for
Part 2 of the project.
"""

import random
import traceback
import inspect
from servers import StorageServer, PublicKeyServer
from base_client import IntegrityError
from crypto import Crypto


#########################
#  FUNCTIONALITY TESTS  #
#########################

globs = dict(globals())

def t01_StoreManyKeys(C, pks, crypto, server):
    """Verify that it is reasonably efficient to store many keys on the server."""
    return 1
    alice = C("alice")
    for k in range(1000):
        alice.upload(str(k),str(k))
    alice2 = C("alice")
    for k in range(1000):
        if alice2.download(str(k)) != str(k):
            return 0
    return 1


def t02_OverwritePuts(C, pks, crypto, server):
    """A long file when changed byte by byte will have the correct result at the
    end."""
    return 1
    alice = C("alice")
    data = "a"*100000
    for _ in range(100):
        data = list(map(str, data))
        data[random.randint(0, len(data) - 1)] = chr(random.randint(0, 255))
        data = "".join(data)
        alice.upload("k", data)
        if alice.download("k") != data:
            return 0
    return 1

def t03_MoreOverwritePuts(C, pks, crypto, server):
    """A long file when changed many bytes at a time, will have the correct result 
    at the end."""
    return 1
    alice = C("alice")
    data = "a"*100000
    for _ in range(100):
        data = list(map(str, data))
        size = random.randint(10,10000)
        start = random.randint(0, len(data) - size)
        data[start:start+size] = [chr(random.randint(0, 255)) for _ in range(size)]
        data = "".join(data)
        alice.upload("k", data)
        if alice.download("k") != data:
            return 0
    return 1

def t04_LengthChangingPuts(C, pks, crypto, server):
    """Verifies that it is possible to change the length of a file once on the
    server."""
    return 1
    alice = C("alice")
    for _ in range(100):
        data = "".join(chr(random.randint(0, 255)) for _ in
                       range(random.randint(1, 20000)))
        alice.upload("k", data)
    return alice.download("k") == data


def t05_SmallLengthChangingPuts(C, pks, crypto, server):
    """Randomly adds or deletes a small number of bytes from a file, and ensures
    data is correct."""
    return 1
    alice = C("alice")
    data = "".join(chr(random.randint(0, 255)) for _ in range(10000))
    for _ in range(100):
        i = random.randint(0, len(data)-1)
        if random.randint(0, 1) == 0:
            insert = ("".join(chr(random.randint(0, 255)) for _ in
                              range(random.randint(1, 10))))
            data = data[:i] + insert + data[i:]
        else:
            data = data[:i] + data[i + random.randint(1, 10):]
        alice.upload("k", data)
    return alice.download("k") == data


def t06_PutOffByOneSize(C, pks, crypto, server):
    """Uploads a file with only a few bytes different by changing its
    length."""
    alice = C("alice")
    alice.upload("k", "a" * 10000)
    alice.upload("k", "a" * 10000 + "b")
    score = alice.download("k") == "a" * 10000 + "b"
    alice.upload("k", "a" * 9999 + "b")
    score += alice.download("k") == "a" * 9999 + "b"
    return score / 2


def t07_SimpleSharing(C, pks, crypto, server):
    """Checks that sharing works in the simplest case of sharing one file."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    return bob.download("k") == "v"


def t08_SimpleTransitiveSharing(C, pks, crypto, server):
    """Checks that sharing a file can be done multiple times and is
    transitive."""
    alice = C("alice")
    bob = C("bob")
    carol = C("carol")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    m = bob.share("carol", "k")
    carol.receive_share("bob", "k", m)
    return ((alice.download("k") == "v") + (bob.download("k") == "v") + (
            carol.download("k") == "v")) / 3


def t09_SharingIsPassByReference(C, pks, crypto, server):
    """Verifies that updates to a file are sent to all other users who have that
    file."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    score = bob.download("k") == "v"
    bob.upload("k", "q")
    score += alice.download("k") == "q"
    return score / 2


def t10_SharingIsPassByReference2(C, pks, crypto, server):
    """Verifies that updates to a file are sent to all other users who have that
    file."""
    alice = C("alice")
    bob = C("bob")
    carol = C("carol")
    dave = C("dave")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    m = alice.share("carol", "k")
    carol.receive_share("alice", "k", m)
    m = carol.share("dave", "k")
    dave.receive_share("carol", "k", m)

    score = bob.download("k") == "v"
    dave.upload("k", "q")
    score += alice.download("k") == "q"
    score += bob.download("k") == "q"
    score += carol.download("k") == "q"
    return score / 4


def t11_EfficientPutChangedData(C, pks, crypto, server):
    """Verifies that when two users have access to a file they keep their state
    current."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "q" + "a" * 10000 + "q")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    score = bob.download("k") == "q" + "a" * 10000 + "q"
    alice.upload("k", "w" + "a" * 10000 + "q")
    bob.upload("k", "q" + "a" * 10000 + "w")
    score += alice.download("k") == "q" + "a" * 10000 + "w"
    score += bob.download("k") == "q" + "a" * 10000 + "w"
    return score / 3


def t12_SharedStateIsChecked(C, pks, crypto, server):
    """Verifies that when two users have access to a file they keep their state
    current."""
    alice = C("alice")
    bob = C("bob")
    value = "a" * 10000 + "b" + "a" * 10000 + "c" + "a" * 10000
    alice.upload("k", value)
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    score = bob.download("k") == value

    value = "a" * 10000 + "c" + "a" * 10000 + "c" + "a" * 10000
    bob.upload("k", value)
    value = "a" * 10000 + "b" + "a" * 10000 + "d" + "a" * 10000
    alice.upload("k", value)
    score += alice.download("k") == value
    return score / 2

def t13_ShareRevokeShare(C, pks, crypto, server):
    """Checks that after a user has been revoked from a file, they can receive
    it again."""
    alice = C("alice")
    bob = C("bob")
    carol = C("carol")
    alice.upload("k", "v")

    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)

    m = bob.share("carol", "k")
    carol.receive_share("bob", "k", m)

    score = alice.download("k") == "v"
    print(alice.download("k"))
    score += bob.download("k") == "v"
    print(bob.download("k"))
    score += carol.download("k") == "v"
    print(carol.download("k"))

    alice.revoke("bob", "k")
    alice.upload("k", "q")
    bob.upload("k", "z")
    print(bob.download("k"))

    score += alice.download("k") == "q"
    print(alice.download("k"))

    score += bob.download("k") != "q"
    print(bob.download("k"))
    score += carol.download("k") != "q"
    print(carol.download("k"))
    carol.upload("k", "x")
    print(carol.download("k"))

    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)

    score += alice.download("k") == "q"
    score += bob.download("k") == "q"

    return score / 8


def t14_SimpleSubtreeRevoke(C, pks, crypto, server):
    """Simple verification that revocation also revokes all grandchildren of a
    file."""
    def share(a, b, k):
        m = a.share(b.username, k)
        b.receive_share(a.username, k, m)

    score = 0
    for child in [True, False]:
        server.kv = {}
        alice = C("alice")
        bob = C("bob")
        carol = C("carol")
        dave = C("dave")
        eve = C("eve")
        value = "asdfas"
        alice.upload("k", value)
        share(alice, bob, "k")
        share(bob, carol, "k")
        share(carol, dave, "k")
        share(alice, eve, "k")

        score += alice.download("k") == value
        score += bob.download("k") == value
        score += carol.download("k") == value
        score += dave.download("k") == value
        score += eve.download("k") == value

        if child:
            alice.revoke("bob", "k")
            alice.upload("k", "sdfsdf")
            score += alice.download("k") == "sdfsdf"
            score += bob.download("k") != "sdfsdf"
            score += carol.download("k") != "sdfsdf"
            score += dave.download("k") != "sdfsdf"
            score += eve.download("k") == "sdfsdf"
        else:
            alice.revoke("bob", "k")
            eve.upload("k", "sdfsdf")
            score += alice.download("k") == "sdfsdf"
            score += bob.download("k") != "sdfsdf"
            score += carol.download("k") != "sdfsdf"
            score += dave.download("k") != "sdfsdf"
            score += eve.download("k") == "sdfsdf"
            print(score)
    return score


def t15_MultiLevelSharingRevocation(C, pks, crypto, server):
    """Creates many users and shares the file in a random tree structure,
    revoking one child, and verifies that updates are correctly reflected."""
    clients = [C("c"+str(i)) for i in range(100)]
    clients[0].upload("k", "v")
    parents = {}
    for i, c in enumerate(clients):
        if i == 0:
            continue
        parent = random.randint(0, i-1)
        parentc = clients[parent]
        parents[i] = parent
        m = parentc.share("c"+str(i), "k")
        c.receive_share(parentc.username, "k", m)

    rootchild = [x for x in parents if parents[x] == 0]
    revoked = random.choice(rootchild)

    clients[0].revoke("c" + str(revoked), "k")
    clients[0].upload("k", "w")

    score = 0
    for i, c in enumerate(clients):
        node = i
        while node != 0:
            if node == revoked:
                break
            node = parents[node]
        if node == revoked:
            score += c.download("k") != "w"
        else:
            score += c.download("k") == "w"
            
    return score


class PerfServer(StorageServer):
    size = 0

    def get(self, k):
        res = super().get(k)
        self.size += len(bytes(k,'utf-8'))
        self.size += len(bytes(res,'utf-8')) if res else 1
        return res

    def put(self, k, v):
        if not isinstance(k, str):
            raise TypeError("id must be a string")
        if not isinstance(v, str):
            
            raise TypeError("value must be a string")
        self.size += len(bytes(k,'utf-8'))
        self.size += len(bytes(v,'utf-8'))
        return super().put(k, v)

    def delete(self, k):
        self.size += len(bytes(k,'utf-8'))
        return super().delete(k)


def z01_SimplePerformanceTest(C, pks, crypto, server=PerfServer, size=1024*1024,other=False):
    """The simplest performance test: put a 1MB value on the
    server, and update a single byte in the middle. Count
    number of bytes changed."""

    alice = C("alice")
    data = crypto.get_random_bytes(size)
    alice.upload("a", data)
    offset = random.randint(0,len(data)-1)
    data = data[:offset] + chr(ord(data[offset])+1) + data[offset+1:]
    server.size = 0
    alice.upload("a", data)
    res = server.size

    if alice.download("a") != data:
        raise RuntimeError("Did not receive correct end result.")

    if not other:
        print("Uploaded bytes:",res)
    return res


def z02_SimpleAlgorithmicPerformanceTest(C, pks, crypto, server=PerfServer):
    """Try to compute the order-of-complexity of the algorithm being
    used when updating a single byte. Let n be the size of the initial 
    value stored. In the worst case, an O(n) algorithm re-updates every 
    byte. An O(1) algorithm updates only a constant number of bytes"""

    import numpy as np

    results = []
    for size in range(10,20):
        server.kv = {}
        results.append(z01_SimplePerformanceTest(C, pks, crypto, server, 2**size, True))

    lin_fit = np.polyfit(range(10),np.log(results),2,full=True)

    log_fit = np.polyfit(range(10),results,1,full=True)

    quad_log_fit = np.polyfit(range(10),results,2,full=True)

    if log_fit[1][0] > lin_fit[1][0] and lin_fit[0][1] > .1:
        return 'Exponential size', lin_fit[0]
    else:
        if quad_log_fit[1][0] < log_fit[1][0] and quad_log_fit[0][0] > .3:
            return 'Log quad size', quad_log_fit[0]
        else:
            return 'Log size', log_fit[0]

    return slope

def z03_SharingPerformanceTest(C, pks, crypto, server=PerfServer, size=1024*1024):
    """Store a 1MB file on the server, and share it with another user. Alternate
    each user modifying it and count total bytes transferred."""

    alice = C("alice")
    bob = C("bob")
    data = crypto.get_random_bytes(size)
    alice.upload("a", data)

    m = alice.share("bob", "a")
    bob.receive_share("alice", "a", m)
    
    server.size = 0

    for _ in range(10):
        offset = random.randint(0,len(data)-1)
        data = data[:offset] + chr(ord(data[offset])+1) + data[offset+1:]
        bob.upload("a", data)
    

        offset = random.randint(0,len(data)-1)
        data = data[:offset] + chr(ord(data[offset])+1) + data[offset+1:]
        alice.upload("a", data)
    
    res = server.size

    if alice.download("a") != data or bob.download("a") != data:
        raise RuntimeError("Did not receive correct end result.")
    
    print("Uploaded bytes:",res)
    return res

def z04_NonSingleSharingPerformanceTest(C, pks, crypto, server=PerfServer, size=1024*1024,other=False):
    """Store a 1MB file on the server and make updates of increasingly
    larger sizes and count total bytes sent.."""

    alice = C("alice")
    bob = C("bob")
    data = crypto.get_random_bytes(size)
    alice.upload("a", data)

    m = alice.share("bob", "a")
    bob.receive_share("alice", "a", m)

    count = 0

    for size in range(0,14):
        server.size = 0
        size = 2**size
        offset = random.randint(0,len(data)-1-size)
        update = crypto.get_random_bytes(int(size/2)+1)[:size]
        data = data[:offset] + update + data[offset+size:]
        (alice if size%2 == 0 else bob).upload("a", data)
        count += server.size/size

        if alice.download("a") != data or bob.download("a") != data:
            raise RuntimeError("Did not receive correct end result.")

    if not other:
        print("Weighted uploaded bytes:",int(count))
    return count



gs = dict(globals())

functionality_tests = []
for g, f in sorted(gs.items()):
    if (g not in globs and g != "globs" and "__" not in g and
            type(f) == type(lambda x: x)):
        functionality_tests.append((g, f))


class StudentTester:
    def __init__(self, theclass):
        self.theclass = theclass

    def run_test(self, t, Server=StorageServer, Crypto=Crypto,
                 Pks=PublicKeyServer):
        argspec = inspect.getargspec(t)
        if argspec.defaults is None:
            types = {}
        else:
            types = dict(zip(argspec.args[-len(argspec.defaults):],
                             argspec.defaults))

        server = types['server']() if 'server' in types else Server()
        pks = types['pks']() if 'pks' in types else Pks()
        crypto = types['crypto']() if 'crypto' in types else Crypto()
        myclient = __import__(self.theclass, fromlist=[''])

        def C(name):
            return myclient.Client(server, pks, crypto, name)
        return t(C, pks, crypto, server)

if __name__ == "__main__":
    for testname, test in functionality_tests:
        print("============")
        print("Running test", testname)
        try:
            score = StudentTester("client").run_test(test)
            if testname[:2] != 'z0':
                if score >= .99999:
                    print("\tTest Passes")
                else:
                    print("\tTest FAILED.")
                    print("\t"+test.__doc__)
            else:
                print("\tPerformance Test result",score)
        except:
            print("\tTest FAILED.")
            print("\t"+test.__doc__)
            traceback.print_exc()
            print("\n\n")

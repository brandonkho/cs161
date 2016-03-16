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


def t01_OverwritePuts(C, pks, crypto, server):
    """A long file when changed byte by byte will have the correct result at the
    end."""
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


def t02_LengthChangingPuts(C, pks, crypto, server):
    """Verifies that it is possible to change the length of a file once on the
    server."""
    alice = C("alice")
    for _ in range(100):
        data = "".join(chr(random.randint(0, 255)) for _ in
                       range(random.randint(1, 20000)))
        alice.upload("k", data)
    return alice.download("k") == data


def t03_SmallLengthChangingPuts(C, pks, crypto, server):
    """Randomly adds or deletes a small number of bytes from a file, and ensures
    data is correct."""
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


def t04_PutOffByOneSize(C, pks, crypto, server):
    """Uploads a file with only a few bytes different by changing its
    length."""
    alice = C("alice")
    alice.upload("k", "a" * 10000)
    alice.upload("k", "a" * 10000 + "b")
    score = alice.download("k") == "a" * 10000 + "b"
    alice.upload("k", "a" * 9999 + "b")
    score += alice.download("k") == "a" * 9999 + "b"
    return score / 2


def t05_SimpleSharing(C, pks, crypto, server):
    """Checks that sharing works in the simplest case of sharing one file."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("k", "v")
    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)
    return bob.download("k") == "v"


def t06_SimpleTransitiveSharing(C, pks, crypto, server):
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


def t07_SharingIsPassByReference(C, pks, crypto, server):
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


def t08_SharingIsPassByReference2(C, pks, crypto, server):
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


def t09_EfficientPutChangedData(C, pks, crypto, server):
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


def t10_SharedStateIsChecked(C, pks, crypto, server):
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


def t11_ShareRevokeShare(C, pks, crypto, server):
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
    score += bob.download("k") == "v"
    score += carol.download("k") == "v"

    alice.revoke("bob", "k")
    alice.upload("k", "q")

    score += alice.download("k") == "q"
    score += bob.download("k") != "q"
    score += carol.download("k") != "q"

    m = alice.share("bob", "k")
    bob.receive_share("alice", "k", m)

    score += alice.download("k") == "q"
    score += bob.download("k") == "q"

    return score / 8


def t12_SimpleSubtreeRevoke(C, pks, crypto, server):
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
            alice.revoke("carol", "k")
            alice.upload("k", "sdfsdf")
            score += alice.download("k") == "sdfsdf"
            score += bob.download("k") == "sdfsdf"
            score += carol.download("k") != "sdfsdf"
            score += dave.download("k") != "sdfsdf"
            score += eve.download("k") == "sdfsdf"
    return score


def t13_MultiLevelSharingRevocation(C, pks, crypto, server):
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
        self.size += len(bytes(k))
        self.size += len(bytes(res)) if res else 1
        return res

    def put(self, k, v):
        self.size += len(bytes(k))
        self.size += len(bytes(v))
        return super().get(k)

    def delete(self, k):
        self.size += len(bytes(k))
        return super().delete(k)


def z_PerformanceTest(C, pks, crypto, server=PerfServer):
    """Runs a sample performance test, counting bytes sent to/from the
    server."""
    alice = C("alice")
    data = "a"*(1024*1024)
    alice.upload("a", data)
    alice.upload("a", "b"+data[1:])
    print("\tTotal transfer size: ", server.size)
    return True

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
            if StudentTester("client").run_test(test) >= .99999:
                print("\tTest Passes")
            else:
                print("\tTest FAILED.")
                print("\t"+test.__doc__)
        except:
            print("\tTest FAILED.")
            print("\t"+test.__doc__)
            traceback.print_exc()
            print("\n\n")

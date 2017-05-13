# pbkdf2.py -- library to calculate keys from passwords
# Copyright (C) 2010 Tobias Ammann

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of
# the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public
# License along with this program; if not, see
# <http://www.gnu.org/licenses/>.

from math import ceil
from functools import partial
from hashlib import sha1
from hmac import new as hmac

def pbkdf2(password, salt, dk_length, iterations=1000,
           hashfunc=sha1):
    digest_size = hashfunc().digest_size
    prf = partial(hmac, digestmod=hashfunc)
    assert dk_length < 2 ** 32 - 1, 'derived key too long'

    l = int(ceil(float(dk_length) / digest_size))

    def xor(a, b):
        return ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

    def i2b(i):
        i = hex(i)[2:]
        i = '0' * (8 - len(i)) + i
        return i.decode('hex')

    dk = ''

    for b in xrange(1, l + 1):
        u = prf(password, salt + i2b(b)).digest()
        r = u
        for _ in xrange(iterations - 1):
            u = prf(password, u).digest()
            r = xor(r, u)
        dk += r

    return dk[:dk_length]

def main():
    import sys

    try:
        p = sys.argv[1]
        s = sys.argv[2]
        l = int(sys.argv[3])
        i = int(sys.argv[4])
    except:
        print >> sys.stderr, 'Usage:', sys.argv[0], '<password> <salt>', \
            '<length> <iterations>'
        return

    print pbkdf2(p, s, l, i).encode('base64')

if __name__ == '__main__':
    main()

#! /usr/local/bin/python
#-*- coding: utf-8 -*-

__author__ = "Cedric Bonhomme"
__version__ = "$Revision: 0.1 $"
__date__ = "$Date: 2010/10/26 $"
__copyright__ = "Copyright (c) 2009-2010 Cedric Bonhomme"
__license__ = "GPL v3"

"""Tool box.

Basic mathematical functions for cryptography.
"""

import os
import math
import types
import random
import operator
import itertools

#
# Arithmetic functions
#
def gcd_v1(x,y):
    """
    Returns the greatest common divisor of p and q

    >>> gcd(42, 6)
    6
    """
    assert x or y, "both arguments equals to zero " + `x, y`
    while y:
        (x, y) = (y, x%y)
    return abs(x)

def gcd_v2(p, q):
    """
    Returns the greatest common divisor of p and q

    >>> gcd(42, 6)
    6
    """
    if p<q:
        return gcd_v2(q, p)
    if q == 0:
        return p
    return gcd_v2(q, abs(p%q))

def extended_euclid_gcd_v1(a, b):
    """
    Return (d,u,v) such as d == gcd(a,b) == au + bv.
    """
    assert a or b, "bad arguments " + `x, y`
    assert a >= 0 and b >= 0, "bad arguments " + `x, y`
    if b == 0:
        return (a, 1, 0)
    (d, ap, bp) = extended_euclid_gcd_v1(b , a%b)
    return (d, bp, ap - a/b * bp)

def extended_euclid_gcd_v2(a, b):
    """
    Returns a tuple (d, i, j) such that d = gcd(a, b) = ia + jb
    """
    assert x or y, "bad arguments " + `x, y`
    assert x >= 0 and y >= 0, "bad arguments " + `x, y`
    if b == 0:
        return (a, 1, 0)
    q = abs(a % b)
    r = long(a / b)
    (d, k, l) = extended_euclid_gcd_v2(b, q)
    return (d, l, k - l*r)

def log(x, base = 10):
    """
    Return the natural (népérien) logarithm of 'x'.
    """
    return math.log(x) / math.log(base)

def euler(nb):
    """
    Euler.
    """
    return [a for a in range(0,nb) if gcd(a,nb) == 1]


#
# Modular arithmetic functions
#
def fast_exponentiation(a, p, n):
    """
    Calculates r = a^p mod n
    """
    result = a % n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result

def inv_modulo(a,m):
    """Retourne l'inverse modulaire de a modulo m.
    """
    assert m > 1, "bad arguments " + `a, m`
    (d, x, _) = extended_euclid_gcd_v1(a, m)
    if d == 1:
        return x % m
    return None

def eqn_modulaire(a,b,m):
    """ Resolution de a*x=b%m
    """
    return (b * inv_modulo(a, m)) % m


#
# Classical primality tests.
#
def premier(a, b):
    """
    Return True a and b are coprimes.
    """
    assert a or b, "both arguments are none " + `a, b`
    return gcd(a, b) == 1

def est_premier(n):
    """
    Return True if a number is prime, else False.
    """
    if n == 2:
        return True
    elif (n == 1 or n % 2 == 0):
        return False
    else:
        r = int(math.sqrt(n))
        i = 3
        while i <= r:
            if n % i == 0:
                return 0
            i = i + 2
        return True


#
# Probabilistic primality tests
#

def fermat_little_theorem(p):
    """
    Returns 1 if p may be prime, and something else if p definitely
    is not prime
    """
    a = randint(1, p-1)
    return fast_exponentiation(a, p-1, p)


def miller_rabin_pass(a, n):
    """
    Miller-Rabin. First version.
    """
    d = n - 1
    s = 0
    while d & 1:
        d = d >> 1
        s = s + 1
    a_to_power = expo_modulaire_rapide(a, d, n)
    if a_to_power == 1:
        return True
    for i in xrange(s-1):
        if a_to_power == n - 1:
            return True
        a_to_power = (a_to_power * a_to_power) % n
    return a_to_power == n - 1

def miller_rabin_version1(n):
    for repeat in xrange(20):
        a = 0
        while a == 0:
            a = random.randrange(n)
        if not miller_rabin_pass(a, n):
            return False
    return True

def millerTest(a, i, n):
    """
    Miller-Rabin. Second version.
    """
    if i == 0:
        return 1
    x = millerTest(a, i / 2, n)
    if x == 0:
        return 0
    y = (x * x) % n
    if ((y == 1) and (x != 1) and (x != (n - 1))):
        return 0
    if (i % 2) != 0:
        y = (a * y) % n
    return y

def miller_rabin_version2(n):
    if millerTest(random.randint(2, n - 2), n - 1, n) == 1:
        return True
    return False


# Jacobi
def jacobi(a, b):
    """Calculates the value of the Jacobi symbol (a/b)
    """

    if a % b == 0:
        return 0
    result = 1
    while a > 1:
        if a & 1:
            if ((a-1)*(b-1) >> 2) & 1:
                result = -result
            b, a = a, b % a
        else:
            if ((b ** 2 - 1) >> 3) & 1:
                result = -result
            a = a >> 1
    return result

def jacobi_witness(x, n):
    """Returns False if n is an Euler pseudo-prime with base x, and
    True otherwise.
    """

    j = jacobi(x, n) % n
    f = fast_exponentiation(x, (n-1)/2, n)
    if j == f:
        return False
    return True







def reste_chinois(la,lm):
    """
    Return the solution of the Chinese theorem.
    """
    M = reduce(operator.mul, lm)
    lM = [M/mi for mi in lm]
    ly = map(inv_modulo, lM, lm)
    laMy = map((lambda ai, Mi, yi : ai*Mi*yi), la, lM, ly)
    return sum(laMy) % M

def eratosthenes_prime_gen():
    """
    Generates prime numbers with the sieve of Eratosthenes.
    """
    d = {}
    for i in itertools.count(2):
        if i in d:
            for j in d[i]:
                d[i + j] = d.get(i + j, []) + [j]
            del d[i]
        else:
            d[i * i] = [i]
            yield i

def factorise(n):
    """
    Factor a number.
    """
    factors = []
    for p in eratosthenes_prime_gen():
        if p * p > n:
            break
        while n % p == 0:
            n /= p
            factors.append(p)
    if n != 1:
        factors.append(n)
    return factors

def nombrePremierListe(n):
    """
    Return the list of primes up to n.
    """
    generateur = eratosthenes()
    return [generateur.next() for _ in range(n)]

def all_perms(liste):
    """
    Returns all permutations of a list.
    """
    if len(liste) <=1:
        yield liste
    else:
        for perm in all_perms(liste[1:]):
            for i in range(len(perm)+1):
                yield perm[:i] + liste[0:1] + perm[i:]

def word_frequency(word):
    """Fréquence d'apparition des lettres d'un word.
    """
    dic = {}
    for i in word:
        if i in dic:
            dic[i] = dic[i] + 1
        else:
            dic[i] = 1
    liste = dic.items()
    liste.sort(key = operator.itemgetter(1), reverse = True)
    return liste



def resolve_system(a,b,m):
    """Résolution du système d'équations a et b
    """
    a1 = [(i*b[0])%m for i in a]
    b1 = [(i*a[0])%m for i in b]
    c1 = [(i-j)%m for (i, j) in itertools.izip(a1, b1)]
    y = eqn_modulaire(c1[1], c1[2], m);
    x = eqn_modulaire(a[0], (a[2]-a[1]*y)%m, m)
    return (x,y)

def equation(mat1, mat2):
    """Résolution d'équations.

    Résolution d'un système d'équation affines modulaires.
    """
    c1 = mat1[0] - mat1[1]
    c2 = mat2[0][0] - mat2[0][1]
    c3 = mat2[1][0] - mat2[1][1]
    a, b = 0, 0

    if c1 <= 0:
       c1 = c1 % 31
    if c2 <= 0:
       c2 = c2 % 31

    inv = inv_modulo(c2, 31)
    if inv != None:
        a = (c1 * inv) % 31
    else:
        l = []
        for i in range(1, 31):
            if (c2 * i) % 31 == c1:
                l.append(i)
        for i in l:
            if gcd(31, 6) != 1:
                l.remove(i)
	a = l[0]

    b = (mat1[1] - mat2[0][1] * a) % 31

    return (a, b)


def determinant(matrice):
    return (matrice[0][0] * matrice[1][1]) - \
                    (matrice[1][0] * matrice[0][1])

def systeme_ordre_deux(matrice1, matrice2):
    determinant_denominateur = determinant(matrice1)
    determinant_numerateur1 = determinant([matrice2, [matrice1[1][0], matrice1[1][1]]])
    determinant_numerateur2 = determinant([[matrice1[0][0], matrice1[0][1]], matrice2])

    return ((determinant_numerateur1/determinant_denominateur) ,
            (determinant_numerateur2/determinant_denominateur))

def system2inconnusResolve(x1, y1, x2, y2):
    xtmp = (x1 - x2) % 26
    ytmp = (y1 - y2) % 26
    a = (ytmp * inv_modulo(xtmp, 26)) % 26
    b = (y2 - (x2 * a)) % 26
    return a, b


def racine_cubique(a):
    """Renvoie la racine cubique de a."""
    for i in range(10000):
        if pow(i,3) == a:
            return i
    return None

def invertible(matrix):
    """
    Return True if a 2*2 matrix is inversible in Z26.
    """
    determinant = matrix[0][0] * matrix[1][1] - \
                    matrix[1][0] * matrix[0][1]
    return gcd_v1(determinant, 26) == 1

def inverse_matrix(matrix):
    """
    Inverse a 2*2 matrix.
    """
    if not invertible(matrix):
        return "Non invertible matrix"
    result = [i[:] for i in matrix]
    result[0][0] = matrix[1][1]
    result[1][1] = matrix[0][0]
    result[1][0] = (-matrix[1][0]) % 26
    result[0][1] = (-matrix[0][1]) % 26
    return result


#
# FONCTIONS DE CONVERSIONS
#

def int_to_bin(x, count = 8):
    """Transforme un entier en binaire."""
    return "".join(map(lambda y : str((x >> y) & 1), range(count-1, -1, -1)))

def bin_to_decimal(x):
    """Transforme un binaire en entier."""
    return sum(map(lambda z: int(x[z]) and 2**(len(x) - z - 1),
                   range(len(x)-1, -1, -1)))

def word_to_bin(word, count = 8):
    """Transforme un word en liste de binaires."""
    return [int_to_bin(ord(i), count) for i in word]

def binList_to_word(liste):
    """Transforme une liste de binaires en word."""
    return "".join([chr(bin_to_decimal(i)) for i in liste])

def bytes2int(bytes):
    """
    Converts a list of bytes or a string to an integer

    >>> (128*256 + 64)*256 + + 15
    8405007
    >>> l = [128, 64, 15]
    >>> bytes2int(l)
    8405007
    """
    if not (type(bytes) is types.ListType or type(bytes) is types.StringType):
        raise TypeError("You must pass a string or a list")

    # Convert byte stream to integer
    integer = 0
    for byte in bytes:
        integer *= 256
        if type(byte) is types.StringType: byte = ord(byte)
        integer += byte

    return integer

def int2bytes(number):
    """
    Converts a number to a string of bytes

    >>> bytes2int(int2bytes(123456789))
    123456789
    """

    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("You must pass a long or an int")

    string = ""

    while number > 0:
        string = "%s%s" % (chr(number & 0xFF), string)
        number /= 256
    return string


if __name__ == '__main__':
    # Point of entry in execution mode
    #print equation([3,24], [[4, 19], [1, 1]])
    #print reste_chinois([5, 3, 7], [10, 17, 9])
    #print reste_chinois([4*inv_modulo(13,99),\
                                #56*inv_modulo(15,101)],[99,101])
    #print inv_modulo(8,31)
    #print factorise(121549788)
    #print est_premier(157)
    #print word_to_bin("SALUT")
    #print binList_to_word(word_to_bin("SALUT"))
    #print miller_rabin_version2(100711433)
    print systeme_ordre_deux([[4, 2], [2, 3]], [24, 16])
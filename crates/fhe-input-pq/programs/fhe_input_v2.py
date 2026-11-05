# exp-frames experiment 41, the post-quantum run (Q8), version 2: a TFHE compact public-key
# ciphertext is well formed. A port of the relation tfhe-zk-pok's proof covers, not that proof.
#
# Statement. Public, through the digest: the key (a, b), D coefficients each, and the ciphertext
# (c1, c2), D and K coefficients, in Z_{2^64}. Private: s in {0,1}^D (tfhe-zk-pok's r, reversed),
# e1 in [-2^17, 2^17)^D, e2 in [-2^17, 2^17)^K, m in [0, 16)^K, with, modulo 2^64,
#   c1 = a (*) s + e1                         (*) the negacyclic product mod X^D + 1
#   c2_i = sum_j s_j B(i + j) + e2_i + 2^59 m_i, B(u) = b_{D-1-u} for u < D, -b_{2D-1-u} after.
# Integers are exponents of HGEN, a primitive element of GF(2^192)^*: a coefficient x is HGEN^x,
# a sum of at most D coefficients is below 2^75, far below HGEN's order 2^192 - 1, so sums are
# exact and every equation below is an equation of integers.
#
# Witness streams (each entry's length in cells):
#   pk     D entries of 1: cell t of a then b, coefficients 2t and 2t+1 as its two 64-bit limbs
#   ct     CT entries of 1: c1 then c2 the same way, a last odd coefficient's partner zero
#   bytes  one entry of 8 per limb, pk's then ct's, in order: g^(byte p) for p = 0..7
#   mu     1 entry of 2: the request's message
#   nj     1 entry of 1: g^|J|, J the support of s; nb: g^blocks, 16 * blocks >= |J|
#   jp     16 * blocks entries of 1: g^j for j in J ascending, then g^-D for each padding slot
#   gap    |J| entries of 1: g^(j_0), then g^(j_t - j_{t-1} - 1)
#   e      D + K entries of 5: g^ of the bytes of e + 2^17 (two, then the top in [0, 4)), then
#          g^ of the bytes of tau + 2^12 (two), where sum + e - c = 2^64 tau
#   m      K entries of 1: g^m
#
# Digest: H(H(H(pk), H(ct)), mu), H keccak256 over the cells' bytes. The contract holds
# keccak256(pk) and hashes the ciphertext from its calldata in the same byte order.
# public_input: the two cells of the digest
from snark_lib import *

D = D_PLACEHOLDER
K = K_PLACEHOLDER
CT = CT_PLACEHOLDER
Y_INV = Y_INV_PLACEHOLDER
H17 = H17_PLACEHOLDER
H76 = H76_PLACEHOLDER
# HPOW[256 p + v] = HGEN^(v 256^p), p = 0..9.
HPOW = HPOW_PLACEHOLDER


@inline
def split_cell(word):
    # The two 64-bit limbs of a cell, proven to be its limbs.
    lo = StackBuf(1)
    hint_f192_limbs(lo, word)
    hi = (word + lo[0]) * Y_INV
    assert_in_k(lo[0], hi)
    return lo[0], hi


def coef(limb, tab):
    # HGEN^x for the 64-bit limb x, from its bytes, tied back to it: tab[256 p + v] holds the
    # byte's bits at position p, and tab[2560 + 256 p + v] HGEN^(v 256^p).
    by = StackBuf(8)
    hint_witness(by, "bytes")
    word = 0
    hx = 1
    for p in unroll(0, 8):
        gv = by[p]
        assert log(gv) < 256
        ptr = tab * gv * GEN ** (256 * p)
        word += ptr[1]
        hx *= ptr[GEN ** 2560]
    assert word == limb
    return hx


@inline
def look(tab, gv, p: Const):
    # HGEN^(v 256^p) for g^v, v < 256.
    ptr = tab * gv * GEN ** (2560 + 256 * p)
    return ptr[1]


def check(sum_h, c_h, e: StackBuf(5), tab, extra):
    # sum + e + extra - c = 2^64 tau, e in [-2^17, 2^17), tau in [-2^12, 2^12).
    for i in unroll(0, 4):
        assert log(e[i]) < 256
    assert log(e[2]) < 4
    assert log(e[4]) < 32
    he = look(tab, e[0], 0) * look(tab, e[1], 1) * look(tab, e[2], 2)
    ht = look(tab, e[3], 8) * look(tab, e[4], 9)
    assert sum_h * he * extra / (c_h * H17) == ht / H76
    return


def cells_to(cells, i, tab, pos, neg):
    # Cell i's two coefficients: HGEN^x at pos[1], pos[GEN]; HGEN^-x at neg[1], neg[GEN].
    w = cells[i]
    l0, l1 = split_cell(w)
    x0 = coef(l0, tab)
    x1 = coef(l1, tab)
    pos[1] = x0
    pos[GEN] = x1
    neg[1] = 1 / x0
    neg[GEN] = 1 / x1
    return


def main():
    # The tables: bit patterns, then powers of HGEN.
    tab = HeapBuf(5120)
    for p in unroll(0, 10):
        for v in unroll(0, 256):
            tab[GEN ** (256 * p + v)] = const(v * 256 ** p)
            tab[GEN ** (2560 + 256 * p + v)] = HPOW[256 * p + v]

    # The key and the ciphertext, hashed.
    pk = HeapBuf(D)
    ct = HeapBuf(CT)
    for t in mul_range(1, GEN ** D):
        hint_witness(pk[t:t + 1], "pk")
    for t in mul_range(1, GEN ** CT):
        hint_witness(ct[t:t + 1], "ct")
    hpk = StackBuf(2)
    keccak_cells(pk[0:D], hpk)
    hct = StackBuf(2)
    keccak_cells(ct[0:CT], hct)
    mu = StackBuf(2)
    hint_witness(mu, "mu")
    inner = StackBuf(2)
    keccak(hpk, hct, inner)
    dg = StackBuf(2)
    keccak(inner, mu, dg)
    p0 = GEN ** 0
    p0[1] = dg[0]
    p0[GEN] = dg[1]

    # TA[t], t in [1, 2D): HGEN^-a_t below D, HGEN^a_(t-D) from D; [2D, 3D) holds 1.
    # TB[D + u], u in [0, 2D): B(u). C: c1 then c2.
    TA = HeapBuf(3 * D)
    TB = HeapBuf(3 * D)
    C = HeapBuf(2 * CT)
    junk = HeapBuf(2 * CT)
    for t in mul_range(1, GEN ** (D // 2)):
        tt = t * t
        cells_to(pk, t, tab, TA * tt * GEN ** D, TA * tt)
    bcells = pk * GEN ** (D // 2)
    for t in mul_range(1, GEN ** (D // 2)):
        # b_2t at u = D - 1 - 2t (positive) and u = 2D - 1 - 2t (negative); b_2t+1 one below.
        tt = t * t
        w = bcells[t]
        l0, l1 = split_cell(w)
        x0 = coef(l0, tab)
        x1 = coef(l1, tab)
        pos = TB * GEN ** (2 * D - 2) / tt
        neg = TB * GEN ** (3 * D - 2) / tt
        pos[GEN] = x0
        pos[1] = x1
        neg[GEN] = 1 / x0
        neg[1] = 1 / x1
    for t in mul_range(1, GEN ** D):
        TA[t * GEN ** (2 * D)] = 1
    for t in mul_range(1, GEN ** CT):
        tt = t * t
        cells_to(ct, t, tab, C * tt, junk * tt)
    # An odd count's last coefficient pads the last cell, and is zero.
    if const(2 * CT == D + K + 1):
        assert C[GEN ** (D + K)] == 1

    # J, the support of s: strictly increasing in [0, D), padded with g^-D.
    nj = hint_witness("nj")
    assert log(nj) < D + 1
    nb = hint_witness("nb")
    assert log(nb) < D // 16 + 2
    nslots = nb ** 16
    JP = HeapBuf(nslots)
    JN = HeapBuf(nslots)
    for t in mul_range(1, nslots):
        hint_witness(JP[t:t + 1], "jp")
        JN[t] = 1 / JP[t]
    prev = HeapBuf(nj * GEN)
    prev[1] = 1 / GEN
    for t in mul_range(1, nj):
        gap = hint_witness("gap")
        assert log(gap) < D
        assert JP[t] == prev[t] * GEN * gap
        prev[t * GEN] = JP[t]
    assert log(prev[nj]) < D
    npad = nslots / nj
    assert log(npad) < 16
    pads = JP * nj
    for t in mul_range(1, npad):
        assert pads[t] == 1 / GEN ** D

    # c1 = a (*) s + e1, sixteen rows by sixteen slots a tile: row n multiplies TA[n - j + D].
    for nq in mul_range(1, GEN ** (D // 16)):
        n0 = nq ** 16
        base = TA * n0 * GEN ** D
        acc = HeapBuf(nb ** 16 * GEN ** 16)
        for r in unroll(0, 16):
            acc[GEN ** r] = 1
        for q in mul_range(1, nb):
            jb = JN * q ** 16
            src = acc * q ** 16
            ps = StackBuf(16)
            for u in unroll(0, 16):
                ps[u] = base * jb[GEN ** u]
            for r in unroll(0, 16):
                l = src[GEN ** r]
                for u in unroll(0, 16):
                    pu = ps[u]
                    l = l * pu[GEN ** r]
                src[GEN ** (16 + r)] = l
        fin = acc * nb ** 16
        for r in unroll(0, 16):
            e = StackBuf(5)
            hint_witness(e, "e")
            check(fin[GEN ** r], C[n0 * GEN ** r], e, tab, 1)

    # c2_i = sum_j s_j B(i + j) + e2_i + 2^59 m_i, over the real slots of J.
    for i in mul_range(1, GEN ** K):
        bp = TB * i * GEN ** D
        sm = HeapBuf(nj * GEN)
        sm[1] = 1
        for t in mul_range(1, nj):
            ptr = bp * JP[t]
            sm[t * GEN] = sm[t] * ptr[1]
        e = StackBuf(5)
        hint_witness(e, "e")
        gm = hint_witness("m")
        assert log(gm) < 16
        hm = look(tab, gm * gm * gm * gm * gm * gm * gm * gm, 7)
        check(sm[nj], C[i * GEN ** D], e, tab, hm)
    return

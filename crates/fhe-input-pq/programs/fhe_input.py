# exp-frames experiment 41, the post-quantum run (Q8): a TFHE compact public-key ciphertext is
# well formed. A port of the relation tfhe-zk-pok's proof covers, not that proof.
#
# Statement. Public, through D: the key (a, b), D coefficients each, and the ciphertext (c1, c2),
# D and K coefficients, in Z_{2^64}. Private: s in {0,1}^D (tfhe-zk-pok's r, reversed), e1 in
# [-2^17, 2^17)^D, e2 in [-2^17, 2^17)^K, m in [0, 16)^K, with, modulo 2^64,
#   c1 = a (*) s + e1                         (*) the negacyclic product mod X^D + 1
#   c2_i = sum_j s_j B(i + j) + e2_i + 2^59 m_i, B(u) = b_{D-1-u} for u < D, -b_{2D-1-u} after.
#
# Witness streams (each entry's length in cells):
#   pk     D entries of 1: cell t of a then b, coefficients 2t and 2t+1 as its two 64-bit limbs
#   ct     CT entries of 1: c1 then c2, the same way, a last odd coefficient's partner zero
#   mu     1 entry of 2: the request's message
#   nj     1 entry of 1: g^|J|, J the support of s; nb: g^(blocks), 8 * blocks >= |J|
#   jp     8 * blocks entries of 1: g^j for j in J ascending, then g^-D for each padding slot
#   gap    |J| entries of 1: g^(j_0), then g^(j_t - j_{t-1} - 1)
#   e      D + K entries of 3: g^u, b0, b1 with e + 2^17 = u + 2^16 (b0 + 2 b1)
#   carry  D + K entries of 2: g^(kappa + 2^12), g^(tau + 2^12)
#   m      K entries of 4: m's bits
#
# Digest: D = H(H(H(pk), H(ct)), mu), H keccak256 over the cells' bytes. The contract holds
# keccak256(pk) and hashes the ciphertext from its calldata in the same byte order.
# public_input: the two cells of D
from snark_lib import *

D = D_PLACEHOLDER
K = K_PLACEHOLDER
CT = CT_PLACEHOLDER
Y_TOWER = Y_TOWER_PLACEHOLDER
Y_INV = Y_INV_PLACEHOLDER


@inline
def split_cell(word):
    # The two 64-bit limbs of a cell, proven to be its limbs.
    lo = StackBuf(1)
    hint_f192_limbs(lo, word)
    hi = (word + lo[0]) * Y_INV
    assert_in_k(lo[0], hi)
    return lo[0], hi


def halves(limb):
    # g^(low 32 bits) and g^(high 32 bits) of a 64-bit limb, from its bits, tied back to it.
    bits = StackBuf(64)
    hint_decompose_bits(bits, limb, 64)
    word = 0
    gl = GEN ** 0
    gh = GEN ** 0
    for j in unroll(0, 32):
        bit = bits[j]
        bits[j] = bit * bit
        word += bit * (2 ** j)
        gl *= 1 + bit * (1 + GEN ** (2 ** j))
    for j in unroll(32, 64):
        bit = bits[j]
        bits[j] = bit * bit
        word += bit * (2 ** j)
        gh *= 1 + bit * (1 + GEN ** (2 ** (j - 32)))
    assert word == limb
    return gl, gh


def table_cell(cells, i, lo_pos, hi_pos, lo_neg, hi_neg):
    # Cell i's two coefficients into exponent tables: g^x at the _pos pointers, g^-x at _neg.
    w = cells[i]
    l0, l1 = split_cell(w)
    a, b = halves(l0)
    c, d = halves(l1)
    lo_pos[1] = a
    hi_pos[1] = b
    lo_pos[GEN] = c
    hi_pos[GEN] = d
    lo_neg[1] = 1 / a
    hi_neg[1] = 1 / b
    lo_neg[GEN] = 1 / c
    hi_neg[GEN] = 1 / d
    return


@inline
def pow2k(x, k: Const):
    # x^(2^k): k squarings.
    y = x
    for i in unroll(0, k):
        y = y * y
    return y


@inline
def noise(e):
    # g^e for e in [-2^17, 2^17), from g^u (u < 2^16) and two bits.
    gu = e[0]
    assert log(gu) < 65536
    b0 = e[1]
    b1 = e[2]
    assert b0 * b0 == b0
    assert b1 * b1 == b1
    v = (1 + b0 * (1 + GEN ** 65536)) * (1 + b1 * (1 + GEN ** 131072))
    return gu * v / GEN ** 131072


@inline
def carried(sum_g, e_g, coef_g, k):
    # sum + e - coef = 2^32 kappa, kappa in [-2^12, 2^12): returns g^kappa.
    assert log(k) < 8192
    gk = k / GEN ** 4096
    assert sum_g * e_g / coef_g == pow2k(gk, 32)
    return gk


def check_coef(sl, sh, el, ch, cl, cg, extra_hi):
    # One coefficient: low halves carry kappa into the high halves, which carry tau out.
    gk = carried(sl, el, cl, cg[0])
    gt = carried(sh * extra_hi, gk, ch, cg[GEN])
    return


def main():
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
    p = GEN ** 0
    p[1] = dg[0]
    p[GEN] = dg[1]

    # Exponent tables. TA, for a: index t in [1, 2D) of the low half holds g^-a_t (t < D) or
    # g^a_(t-D); [2D, 3D) holds 1, for padding. The high halves sit 3D further on.
    # TB, for b: index D + u holds B(u) for u in [0, 2D), [0, D) holds 1.
    # C: c1 then c2, low halves, then high halves CT2 further on.
    TA = HeapBuf(6 * D)
    TB = HeapBuf(6 * D)
    C = HeapBuf(4 * CT)
    for t in mul_range(1, GEN ** (D // 2)):
        tt = t * t
        table_cell(pk, t, TA * tt * GEN ** D, TA * tt * GEN ** (4 * D), TA * tt, TA * tt * GEN ** (3 * D))
    for t in mul_range(1, GEN ** (D // 2)):
        # b_{2t}, b_{2t+1} at B(u) with u = D - 1 - 2t (positive) and u = 2D - 1 - 2t (negative):
        # b_{2t+1} first in u order, so the cell's pair lands reversed.
        tt = t * t
        cell = pk * GEN ** (D // 2)
        w = cell[t]
        l0, l1 = split_cell(w)
        a0, b0 = halves(l0)
        a1, b1 = halves(l1)
        pos = TB * GEN ** (2 * D - 2) / tt
        neg = TB * GEN ** (3 * D - 2) / tt
        pos[GEN] = a0
        pos[GEN ** (3 * D + 1)] = b0
        pos[1] = a1
        pos[GEN ** (3 * D)] = b1
        neg[GEN] = 1 / a0
        neg[GEN ** (3 * D + 1)] = 1 / b0
        neg[1] = 1 / a1
        neg[GEN ** (3 * D)] = 1 / b1
    for t in mul_range(1, GEN ** D):
        TA[t * GEN ** (2 * D)] = 1
        TA[t * GEN ** (5 * D)] = 1
        TB[t] = 1
        TB[t * GEN ** (3 * D)] = 1
    for t in mul_range(1, GEN ** CT):
        w = ct[t]
        l0, l1 = split_cell(w)
        a0, b0 = halves(l0)
        a1, b1 = halves(l1)
        tt = t * t
        C[tt] = a0
        C[tt * GEN] = a1
        C[tt * GEN ** (2 * CT)] = b0
        C[tt * GEN ** (2 * CT + 1)] = b1
    # An odd count's last coefficient pads the last cell, and is zero.
    if const(2 * CT == D + K + 1):
        assert C[GEN ** (D + K)] == 1
        assert C[GEN ** (D + K + 2 * CT)] == 1

    # J, the support of s: strictly increasing in [0, D), padded with g^-D.
    nj = hint_witness("nj")
    assert log(nj) < D + 1
    nb = hint_witness("nb")
    assert log(nb) < D // 8 + 2
    nslots = nb ** 8
    JP = HeapBuf(nslots)
    JN = HeapBuf(nslots)
    for t in mul_range(1, nslots):
        hint_witness(JP[t:t + 1], "jp")
        JN[t] = 1 / JP[t]
    prev = HeapBuf(nj * GEN)
    prev[1] = GEN ** 0 / GEN
    for t in mul_range(1, nj):
        gap = hint_witness("gap")
        assert log(gap) < D
        assert JP[t] == prev[t] * GEN * gap
        prev[t * GEN] = JP[t]
    assert log(prev[nj]) < D
    # Fewer than eight padding slots, each g^-D.
    npad = nslots / nj
    assert log(npad) < 8
    pads = JP * nj
    for t in mul_range(1, npad):
        assert pads[t] == 1 / GEN ** D

    # c1 = a (*) s + e1: row n multiplies TA at n - j + D over J, eight slots a block.
    for n in mul_range(1, GEN ** D):
        base = TA * n * GEN ** D
        accL = HeapBuf(nb * GEN)
        accH = HeapBuf(nb * GEN)
        accL[1] = 1
        accH[1] = 1
        for q in mul_range(1, nb):
            jb = JN * q ** 8
            l = accL[q]
            h = accH[q]
            for u in unroll(0, 8):
                ptr = base * jb[GEN ** u]
                l = l * ptr[1]
                h = h * ptr[GEN ** (3 * D)]
            accL[q * GEN] = l
            accH[q * GEN] = h
        e = StackBuf(3)
        hint_witness(e, "e")
        cg = HeapBuf(2)
        hint_witness(cg[0:2], "carry")
        check_coef(accL[nb], accH[nb], noise(e), C[n * GEN ** (2 * CT)], C[n], cg, GEN ** 0)

    # c2_i = sum_j s_j B(i + j) + e2_i + 2^59 m_i, over the real slots of J.
    for i in mul_range(1, GEN ** K):
        bp = TB * i * GEN ** D
        sL = HeapBuf(nj * GEN)
        sH = HeapBuf(nj * GEN)
        sL[1] = 1
        sH[1] = 1
        for t in mul_range(1, nj):
            ptr = bp * JP[t]
            sL[t * GEN] = sL[t] * ptr[1]
            sH[t * GEN] = sH[t] * ptr[GEN ** (3 * D)]
        e = StackBuf(3)
        hint_witness(e, "e")
        mb = StackBuf(4)
        hint_witness(mb, "m")
        gm = GEN ** 0
        for j in unroll(0, 4):
            bit = mb[j]
            mb[j] = bit * bit
            gm *= 1 + bit * (1 + GEN ** (2 ** (27 + j)))
        cg = HeapBuf(2)
        hint_witness(cg[0:2], "carry")
        k = i * GEN ** D
        check_coef(sL[nj], sH[nj], noise(e), C[k * GEN ** (2 * CT)], C[k], cg, gm)
    return

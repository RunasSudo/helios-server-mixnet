#    Copyright © 2016 RunasSudo (Yingtong Li)
#    Based on code by GRnet researchers (https://github.com/grnet/zeus), licensed under the GPLv3.    
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from bisect import bisect_right

def gamma_decode(sumus, nr_candidates=None, max_choices=None):
    nr_candidates, max_choices = \
        get_choice_params(nr_candidates, nr_candidates, max_choices)

    sumus -= 1
    if sumus <= 0:
        return []

    offsets = get_offsets(nr_candidates)
    nr_choices = bisect_right(offsets, sumus)
    sumus -= offsets[nr_choices - 1]

    choices = []
    append = choices.append
    b = nr_candidates - nr_choices
    i = nr_choices
    while 1:
        choice, sumus = divmod(sumus, get_factor(b, i))
        append(choice)
        if i <= 1:
            break
        i -= 1

    return choices

def get_choice_params(nr_choices, nr_candidates=None, max_choices=None):
    if nr_candidates is None:
        nr_candidates = nr_choices
    if max_choices is None:
        max_choices = nr_candidates

    if nr_choices < 0 or nr_candidates <= 0 or max_choices <= 0:
        m = ("invalid parameters not (%d < 0 or %d <= 0 or %d <= 0)"
             % (nr_choices, nr_candidates, max_choices))
        raise ValueError(m)

    if nr_choices > max_choices:
        m = ("Invalid number of choices (%d expected up to %d)" %
             (nr_choices, max_choices))
        raise AssertionError(m)

    return nr_candidates, max_choices

_terms = {}

def get_term(n, k):
    if k >= n:
        return 1

    if n in _terms:
        t = _terms[n]
        if k in t:
            return t[k]
    else:
        t = {n:1}
        _terms[n] = t

    m = k
    while 1:
        m += 1
        if m in t:
            break

    term = t[m]
    while 1:
        term *= m
        m -= 1
        t[m] = term
        if m <= k:
            break

    return term

_offsets = {}

def get_offsets(n):
    if n in _offsets:
        return _offsets[n]

    factor = 1
    offsets = []
    append = offsets.append
    sumus = 0
    i = 0
    while 1:
        sumus += get_term(n, n-i)
        append(sumus)
        if i == n:
            break
        i += 1

    _offsets[n] = offsets
    return offsets

_factors = {}

def get_factor(b, n):
    if n <= 1:
        return 1

    if b in _factors:
        t = _factors[b]
        if n in t:
            return t[n]
    else:
        t = {1: 1}
        _factors[b] = t

    i = n
    while 1:
        i -= 1
        if i in t:
            break

    f = t[i]
    while 1:
        f *= b + i
        i += 1
        t[i] = f
        if i >= n:
            break

    return f

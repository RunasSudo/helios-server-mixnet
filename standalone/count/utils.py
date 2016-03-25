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

# ----- COMMON CLASSES AND FUNCTIONS -----
from fractions import Fraction
import sys

class Ballot:
	SHOW_IDS = False
	
	def __init__(self, preferences, candidates, value=1):
		global args
		
		self.rawPreferences = preferences
		self.preferences = [candidates[x] for x in preferences]
		
		self.value = self.origValue = Fraction(value)
	
	def prettyPreferences(self):
		return self.rawPreferences if Ballot.SHOW_IDS else [candidate.name for candidate in self.preferences]

class Candidate:
	def __init__(self, name):
		self.name = name
		self.ctvv = Fraction('0')
		self.ballots = []

def readBLT(electionLines):
	ballotData = [] # Can't process until we know the candidates
	candidates = []
	
	# Read first line
	numCandidates = int(electionLines[0].split(' ')[0])
	seats = int(electionLines[0].split(' ')[1])
	
	# Read ballots
	for i in range(1, len(electionLines)):
		if electionLines[i] == '0': # End of ballots
			break
		bits = electionLines[i].split(' ')
		preferences = [int(x) - 1 for x in bits[1:] if x != '0']
		ballotData.append((bits[0], preferences))
	
	# Read candidates
	for j in range(i + 1, len(electionLines)):
		candidates.append(Candidate(electionLines[j].strip('"')))
	
	assert len(candidates) == numCandidates
	
	# Process ballots
	ballots = []
	for ballot in ballotData:
		ballots.append(Ballot(ballot[1], candidates, ballot[0]))
	
	return ballots, candidates, seats

def writeBLT(ballots, candidates, seats, outFile=sys.stdout):
	print("{} {}".format(len(candidates), seats), file=outFile)
	
	for ballot in ballots:
		if ballot.preferences:
			print("{} {} 0".format(ballot.value, " ".join(str(candidates.index(x) + 1) for x in ballot.preferences)), file=outFile)
		else:
			print("{} 0".format(ballot.value), file=outFile)
	
	print("0", file=outFile)
	
	for candidate in candidates:
		print('"{}"'.format(candidate.name), file=outFile)

# ----- HELIOS GAMMA STUFF -----

from bisect import bisect_right

def to_relative_answers(choices, nr_candidates):
    """
    Answer choices helper, convert absolute indexed answers to relative.

    e.g. for candidates [A, B, C] absolute choices [1, 2, 0] will be converted
    to [1, 1, 0].
    """
    relative = []
    candidates = list(range(nr_candidates))
    choices = [candidates.index(c) for c in choices]
    for choice in choices:
        index = candidates.index(choice)
        relative.append(index)
        candidates.remove(choice)

    return relative

def to_absolute_answers(choices, nr_candidates):
    """
    Inverts `to_relative_answers` result.
    """
    absolute_choices = []
    candidates = list(range(nr_candidates))
    tmp_cands = candidates[:]
    for choice in choices:
        choice = tmp_cands[choice]
        absolute_choices.append(candidates.index(choice))
        tmp_cands.remove(choice)
    return absolute_choices

def gamma_encode(choices, nr_candidates=None, max_choices=None):
    nr_choices = len(choices)
    nr_candidates, max_choices = \
        get_choice_params(nr_choices, nr_candidates, max_choices)
    if not nr_choices:
        return 0

    offsets = get_offsets(nr_candidates)
    sumus = offsets[nr_choices - 1]

    b = nr_candidates - nr_choices
    i = 1
    while 1:
        sumus += choices[-i] * get_factor(b, i)
        if i >= nr_choices:
            break
        i += 1

    sumus += 1
    return sumus

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

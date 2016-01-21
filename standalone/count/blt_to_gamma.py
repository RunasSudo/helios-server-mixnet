#!/usr/bin/env python
#    Copyright © 2016 RunasSudo (Yingtong Li)
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

# I love the smell of Python 3 in the morning

import utils
import sys

ballotsIn = sys.argv[1]

ballots = []
candidates = []
with open(ballotsIn, 'r') as ballotsFile:
	ballotsLines = ballotsFile.read().splitlines()
	for i in range(1, len(ballotsLines)):
		if ballotsLines[i] == '0': # End of ballots
			break
		prefs = ballotsLines[i].split(' ')
		ballot = [int(x) - 1 for x in prefs[1:]]
		for i in range(0, int(prefs[0])):
			ballots.append(ballot)
	for j in range(i + 1, len(ballotsLines) - 1):
		candidates.append(ballotsLines[j].strip('"'))

gammas = []
for ballot in ballots:
	try:
		gammas.append(utils.gamma_encode(utils.to_relative_answers(ballot, len(candidates)), len(candidates)))
	except Exception as e:
		print(e, file=sys.stderr)
		print(ballot, file=sys.stderr)

print([gammas])
#print([candidates[y]] for x in utils.gamma_decode(gammas, len(candidates))])

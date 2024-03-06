#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

candidatesIn = sys.argv[1]
ballotsIn = sys.argv[2]

with open(candidatesIn, 'r') as candidatesFile:
	candidates = candidatesFile.read().splitlines()

with open(ballotsIn, 'r') as ballotsFile:
	ballots = ballotsFile.read().splitlines()
	for i in range(0, len(ballots)):
		ballots[i] = ballots[i].split(',')

gammas = []
for ballot in ballots:
	gammas.append(utils.gamma_encode(utils.to_relative_answers([candidates.index(x) for x in ballot], len(candidates)), len(candidates)))

print([gammas])
#print([candidates[y]] for x in utils.gamma_decode(gammas, len(candidates))])

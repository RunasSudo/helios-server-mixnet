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

# ily Python 3
from __future__ import print_function, unicode_literals

import json
import sys

shuffleOut = sys.argv[1]
proofOut = sys.argv[2]

shufs_list = []
proofs_list = []

numQ = (len(sys.argv) - 3) / 2

for i in xrange(0, numQ):
	with open(sys.argv[3 + i], 'r') as f:
		shufs_list.extend(json.load(f))
	with open(sys.argv[3 + numQ + i], 'r') as f:
		proofs_list.extend(json.load(f))

with open(shuffleOut, 'w') as shuffleFile:
	json.dump(shufs_list, shuffleFile)
with open(proofOut, 'w') as proofFile:
	json.dump(proofs_list, proofFile)

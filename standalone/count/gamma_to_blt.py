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
import argparse, itertools, json, sys

parser = argparse.ArgumentParser(description='Convert a Helios election result to an OpenSTV blt file.')

parser.add_argument('election', help='Helios-style election.json specifying candidates')
parser.add_argument('result', help='Helios-style gamma encoded result.json specifying ballots')
parser.add_argument('seats', type=int, help='The number of candidates to elect')
parser.add_argument('question', type=int, help='The question number to tally', nargs='?', default=0)
args = parser.parse_args()

candidates = []
with open(args.election, 'r') as electionFile:
	election = json.load(electionFile)
	
	candidates = []
	for candidate in election["questions"][args.question]["answers"]:
		candidates.append(utils.Candidate(candidate.split("/")[0])) # Just want the name

with open(args.result, 'r') as resultFile:
	results = json.load(resultFile)
	
	result_squashed = [x[0] if isinstance(x, list) else x for x in results[args.question]]
	
	ballots = []
	# Preprocess groups
	for result, group in itertools.groupby(sorted(result_squashed)):
		preferences = utils.to_absolute_answers(utils.gamma_decode(result, len(candidates)), len(candidates))
		ballots.append(utils.Ballot([candidates[x] for x in preferences], None, len(list(group))))

utils.writeBLT(ballots, candidates, args.seats)

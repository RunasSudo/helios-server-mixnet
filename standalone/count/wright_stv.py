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
import argparse, copy, itertools, json, sys
from fractions import Fraction

parser = argparse.ArgumentParser(description='Count an election using Wright STV.')

parser.add_argument('election', help='OpenSTV blt file')
parser.add_argument('--verbose', help='Display extra information', action='store_true')
parser.add_argument('--fast', help="Don't perform a full tally", action='store_true')
parser.add_argument('--quota', help='The quota/threshold condition: >=Droop or >H-B', choices=['geq-droop', 'gt-hb'], default='geq-droop')
parser.add_argument('--ids', help="Display candidate IDs instead of lists of candidates", action='store_true')
parser.add_argument('--countback', help="Store electing quota of votes for a given candidate ID and store in a given blt file", nargs=2)
args = parser.parse_args()

def verboseLog(string):
	global args
	if args.verbose:
		print(string)

def resetCount(ballots, candidates):
	for ballot in ballots:
		ballot.value = ballot.origValue
	for candidate in candidates:
		candidate.ctvv = Fraction('0')
		candidate.ballots.clear()

def distributePreferences(ballots, remainingCandidates):
	exhausted = Fraction('0')
	
	for ballot in ballots:
		isExhausted = True
		for preference in ballot.preferences:
			if preference in remainingCandidates:
				verboseLog("   - Assigning {:.2f} votes to {} via {}".format(float(ballot.value), preference.name, ballot.prettyPreferences))
				
				isExhausted = False
				preference.ctvv += ballot.value
				preference.ballots.append(ballot)
				
				break
		if isExhausted:
			verboseLog("   - Exhausted {:.2f} votes via {}".format(float(ballot.value), ballot.prettyPreferences))
			exhausted += ballot.value
			ballot.value = Fraction('0')
	
	return exhausted

def totalVote(candidates):
	tv = Fraction('0')
	for candidate in candidates:
		tv += candidate.ctvv
	return tv

def calcQuota(candidates, numSeats):
	global args
	if '-hb' in args.quota:
		return totalVote(candidates) / (numSeats + 1)
	if '-droop' in args.quota:
		return (totalVote(candidates) / (numSeats + 1) + 1).__floor__()

def hasQuota(candidate, quota):
	global args
	if 'gt-' in args.quota:
		return candidate.ctvv > quota
	if 'geq-' in args.quota:
		return candidate.ctvv >= quota

# Return the candidate to transfer votes to
def surplusTransfer(preferences, fromCandidate, provisionallyElected, remainingCandidates):
	beginPreference = preferences.index(fromCandidate)
	for index in range(beginPreference + 1, len(preferences)):
		preference = preferences[index]
		if preference in remainingCandidates and preference not in provisionallyElected:
			return preference
	return False

def printVotes(remainingCandidates, provisionallyElected):
	remainingCandidates.sort(key=lambda k: k.ctvv, reverse=True)
	print()
	for candidate in remainingCandidates:
		print("    {}{}: {:.2f}".format("*" if candidate in provisionallyElected else " ", candidate.name, float(candidate.ctvv)))
	print()

def countVotes(ballots, candidates, numSeats, fast):
	global args
	
	count = 1
	remainingCandidates = candidates[:]
	while True:
		print()
		print("== COUNT {}".format(count))
		provisionallyElected = []
		
		resetCount(ballots, candidates)
		exhausted = distributePreferences(ballots, remainingCandidates)
		
		printVotes(remainingCandidates, provisionallyElected)
		
		quota = calcQuota(candidates, numSeats)
		
		print("---- Total Votes: {:.2f}".format(float(totalVote(remainingCandidates))))
		print("---- Exhausted: {:.2f}".format(float(exhausted)))
		print("---- Quota: {:.2f}".format(float(quota)))
		print()
		
		remainingCandidates = sorted(remainingCandidates, key=lambda k: k.ctvv, reverse=True)
		for candidate in remainingCandidates:
			if candidates not in provisionallyElected and hasQuota(candidate, quota):
				print("**** {} provisionally elected".format(candidate.name))
				provisionallyElected.append(candidate)
		
		if fast and len(provisionallyElected) == numSeats:
			return provisionallyElected, exhausted
		
		mostVotesElected = sorted(provisionallyElected, key=lambda k: k.ctvv, reverse=True)
		# While surpluses remain
		while mostVotesElected and mostVotesElected[0].ctvv > quota:
			for candidate in mostVotesElected:
				if candidate.ctvv > quota:
					multiplier = (candidate.ctvv - quota) / candidate.ctvv
					print("---- Transferring surplus from {} at value {:.2f}".format(candidate.name, float(multiplier)))
					
					for ballot in candidate.ballots:
						transferTo = surplusTransfer(ballot.preferences, candidate, provisionallyElected, remainingCandidates)
						if transferTo == False:
							verboseLog("   - Exhausted {:.2f} votes via {}".format(float(ballot.value), ballot.prettyPreferences))
							# exhausted += ballot.value * multiplier
							# Since it retains its value and remains in the count, we will not count it as exhausted.
						else:
							verboseLog("   - Transferring {:.2f} votes to {} via {}".format(float(ballot.value), transferTo.name, ballot.prettyPreferences))
							newBallot = copy.copy(ballot)
							ballot.value *= (1 - multiplier)
							newBallot.value *= multiplier
							transferTo.ctvv += newBallot.value
							transferTo.ballots.append(newBallot)
					
					candidate.ctvv = quota
					
					printVotes(remainingCandidates, provisionallyElected)
					
					for candidate in remainingCandidates:
						if candidate not in provisionallyElected and candidate.ctvv > quota:
							print("**** {} provisionally elected".format(candidate.name))
							provisionallyElected.append(candidate)
					
					if fast and len(provisionallyElected) == numSeats:
						return provisionallyElected, exhausted
			mostVotesElected = sorted(provisionallyElected, key=lambda k: k.ctvv, reverse=True)
		
		# We only want to do this after preferences have been distributed
		if not fast and len(remainingCandidates) == numSeats:
			remainingCandidates.sort(key=lambda k: k.ctvv, reverse=True)
			for candidate in remainingCandidates:
				if candidate not in provisionallyElected:
					print("**** {} provisionally elected on {:.2f} quotas".format(candidate.name, float(candidate.ctvv / quota)))
					provisionallyElected.append(candidate)
			return provisionallyElected, exhausted
		
		# Bulk exclude as many candidates as possible
		remainingCandidates.sort(key=lambda k: k.ctvv)
		grouped = [(x, list(y)) for x, y in itertools.groupby([x for x in remainingCandidates if x not in provisionallyElected], lambda k: k.ctvv)] # ily python
		
		votesToExclude = Fraction('0')
		for i in range(0, len(grouped)):
			key, group = grouped[i]
			votesToExclude += totalVote(group)
		
		candidatesToExclude = []
		for i in reversed(range(0, len(grouped))):
			key, group = grouped[i]
			
			# Would the total number of votes to exclude geq the next lowest candidate?
			if len(grouped) > i + 1 and votesToExclude >= float(grouped[i + 1][0]):
				votesToExclude -= totalVote(group)
				continue
			
			# Would the total number of votes to exclude allow a candidate to reach the quota?
			lowestShortfall = float("inf")
			for candidate in remainingCandidates:
				if candidate not in provisionallyElected and (quota - candidate.ctvv < lowestShortfall):
					lowestShortfall = quota - candidate.ctvv
			if votesToExclude >= lowestShortfall:
				votesToExclude -= totalVote(group)
				continue
			
			# Still here? Okay!
			candidatesToExclude = []
			for j in range(0, i + 1):
				key, group = grouped[j]
				candidatesToExclude.extend(group)
		
		if candidatesToExclude:
			for candidate in candidatesToExclude:
				print("---- Bulk excluding {}".format(candidate.name))
				remainingCandidates.pop(remainingCandidates.index(candidate))
		else:
			# Just exclude one candidate then
			# Check for a tie
			toExclude = 0
			if len(remainingCandidates) > 1 and remainingCandidates[0].ctvv == remainingCandidates[1].ctvv:
				print("---- There is a tie for last place:")
				for i in range(0, len(remainingCandidates)):
					if remainingCandidates[i].ctvv == remainingCandidates[0].ctvv:
						print("     {}. {}".format(i, remainingCandidates[i].name))
				print("---- Which candidate to exclude?")
				toExclude = int(input())
			
			print("---- Excluding {}".format(remainingCandidates[toExclude].name))
			remainingCandidates.pop(toExclude)
		
		if fast and len(remainingCandidates) == numSeats:
			remainingCandidates.sort(key=lambda k: k.ctvv, reverse=True)
			for candidate in remainingCandidates:
				if candidate not in provisionallyElected:
					print("**** {} provisionally elected on {:.2f} quotas".format(candidate.name, float(candidate.ctvv / quota)))
					provisionallyElected.append(candidate)
			return provisionallyElected, exhausted
		
		count += 1

utils.Ballot.SHOW_IDS = args.ids

# Read blt
with open(args.election, 'r') as electionFile:
	electionLines = electionFile.read().splitlines()
	ballots, candidates, args.seats = utils.readBLT(electionLines)

if args.verbose:
	for ballot in ballots:
		print("{:.2f} : {}".format(float(ballot.value), ",".join([x.name for x in ballot.preferences])))

provisionallyElected, exhausted = countVotes(ballots, candidates, args.seats, args.fast)
print()
print("== TALLY COMPLETE")
print()
print("The winners are, in order of election:")

print()
for candidate in provisionallyElected:
	print("     {}".format(candidate.name))
print()

print("---- Exhausted: {:.2f}".format(float(exhausted)))

if args.countback:
	candidate = candidates[int(args.countback[0]) - 1]
	print("== STORING COUNTBACK DATA FOR {}".format(candidate.name))
	
	# Sanity check
	ctvv = 0
	for ballot in candidate.ballots:
		ctvv += ballot.value
	assert ctvv == candidate.ctvv
	
	candidatesToExclude = []
	for peCandidate in provisionallyElected:
		candidatesToExclude.append(peCandidate)
	
	with open(args.countback[1], 'w') as countbackFile:
		utils.writeBLT(candidate.ballots, candidates, 1, candidatesToExclude, countbackFile)

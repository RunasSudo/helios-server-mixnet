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

import argparse, itertools, json, sys
from fractions import Fraction

parser = argparse.ArgumentParser(description='Count an election using instant-runoff voting.')

parser.add_argument('election', help='OpenSTV blt file')
parser.add_argument('--verbose', help='Display extra information', action='store_true')
parser.add_argument('--fast', help="Don't perform a full tally", action='store_true')
parser.add_argument('--ids', help="Display candidate IDs instead of lists of candidates", action='store_true')
args = parser.parse_args()

class Ballot:
	def __init__(self, preferences, candidates, value=1):
		global args
		
		self.rawPreferences = preferences
		self.preferences = [candidates[x] for x in preferences]
		self.prettyPreferences = self.rawPreferences if args.ids else [candidate.name for candidate in self.preferences]
		
		self.value = self.origValue = Fraction(value)
		verboseLog("{:.2f} : {}".format(float(self.value), ",".join([x.name for x in self.preferences])))

class Candidate:
	def __init__(self, name):
		self.name = name
		self.ctvv = Fraction('0')
		self.ballots = []

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

def calcQuota(candidates):
	return totalVote(candidates) / 2

def hasQuota(candidate, quota):
	return candidate.ctvv > quota

# Return the candidate to transfer votes to
def excludedTransfer(preferences, fromCandidate, remainingCandidates):
	beginPreference = preferences.index(fromCandidate)
	for index in range(beginPreference + 1, len(preferences)):
		preference = preferences[index]
		if preference in remainingCandidates:
			return preference
	return False

def exclude(candidate, remainingCandidates):
	remainingCandidates.remove(candidate)
	
	exhausted = 0
	for ballot in candidate.ballots:
		transferTo = excludedTransfer(ballot.preferences, candidate, remainingCandidates)
		if transferTo == False:
			verboseLog("   - Exhausted {:.2f} votes via {}".format(float(ballot.value), ballot.prettyPreferences))
			exhausted += ballot.value
		else:
			verboseLog("   - Transferring {:.2f} votes to {} via {}".format(float(ballot.value), transferTo.name, ballot.prettyPreferences))
			transferTo.ctvv += ballot.value
			transferTo.ballots.append(ballot)
	
	return exhausted

def printVotes(remainingCandidates, quota):
	remainingCandidates.sort(key=lambda k: k.ctvv, reverse=True)
	print()
	for candidate in remainingCandidates:
		print("    {}{}: {:.2f}".format("*" if hasQuota(candidate, quota) else " ", candidate.name, float(candidate.ctvv)))
	print()

def countVotes(ballots, candidates, fast):
	global args
	
	resetCount(ballots, candidates)
	
	remainingCandidates = candidates[:]
	exhausted = distributePreferences(ballots, remainingCandidates)
	
	count = 1
	while True:
		print()
		print("== COUNT {}".format(count))
		
		quota = calcQuota(remainingCandidates)
		
		printVotes(remainingCandidates, quota)
		
		print("---- Total Votes: {:.2f}".format(float(totalVote(remainingCandidates))))
		print("---- Exhausted: {:.2f}".format(float(exhausted)))
		print("---- Majority: {:.2f}".format(float(quota)))
		print()
		
		remainingCandidates = sorted(remainingCandidates, key=lambda k: k.ctvv, reverse=True)
		
		if fast and hasQuota(remainingCandidates[0], quota):
			return remainingCandidates[0], exhausted
		
		if not fast and len(remainingCandidates) <= 2:
			return remainingCandidates[0], exhausted
		
		# Bulk exclude as many candidates as possible
		remainingCandidates.sort(key=lambda k: k.ctvv)
		grouped = [(x, list(y)) for x, y in itertools.groupby(remainingCandidates, lambda k: k.ctvv)] # ily python
		
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
				if not hasQuota(candidate, quota) and (quota - candidate.ctvv < lowestShortfall):
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
				exhausted += exclude(candidate, remainingCandidates)
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
			exhausted += exclude(remainingCandidates[toExclude], remainingCandidates)
		
		if fast and hasQuota(remainingCandidates[0], quota):
			return remainingCandidates[0], exhausted
		
		count += 1

# Read blt

ballotData = [] # Can't process until we know the candidates
candidates = []
with open(args.election, 'r') as electionFile:
	electionLines = electionFile.read().splitlines()
	
	numCandidates = int(electionLines[0].split(' ')[0])
	args.seats = int(electionLines[0].split(' ')[1])
	
	for i in range(1, len(electionLines)):
		if electionLines[i] == '0': # End of ballots
			break
		bits = electionLines[i].split(' ')
		preferences = [int(x) - 1 for x in bits[1:] if x != '0']
		ballotData.append((bits[0], preferences))
	
	for j in range(i + 1, len(electionLines)):
		candidates.append(Candidate(electionLines[j].strip('"')))
	
	assert len(candidates) == numCandidates

ballots = []
for ballot in ballotData:
	ballots.append(Ballot(ballot[1], candidates, ballot[0]))

elected, exhausted = countVotes(ballots, candidates, args.fast)
print()
print("== TALLY COMPLETE")
print()
print("The winner is:")
print("     {}".format(elected.name))

print("---- Exhausted: {:.2f}".format(float(exhausted)))

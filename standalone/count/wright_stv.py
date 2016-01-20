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
import itertools, json, sys
from fractions import Fraction

electionIn = sys.argv[1]
resultIn = sys.argv[2]
question = int(sys.argv[3])
numSeats = int(sys.argv[4])

class Ballot:
	def __init__(self, gamma, candidates):
		self.gamma = gamma
		self.preferences = Ballot.gammaToCandidates(gamma, candidates)
		self.value = Fraction('1')
		print([x.name for x in self.preferences])
	
	def gammaToCandidates(gamma, candidates):
		return [candidates[x] for x in utils.to_absolute_answers(utils.gamma_decode(gamma, len(candidates)), len(candidates))]

class Candidate:
	def __init__(self, name):
		self.name = name
		self.ctvv = Fraction('0')
		self.ballots = []

def resetCount(ballots, candidates):
	for ballot in ballots:
		ballot.value = Fraction('1')
	for candidate in candidates:
		candidate.ctvv = Fraction('0')
		candidate.ballots.clear()

def distributePreferences(ballots, remainingCandidates):
	exhausted = Fraction('0')
	
	for key, group in itertools.groupby(sorted(ballots, key=lambda k: k.gamma), lambda k: k.gamma):
		isExhausted = True
		for preference in Ballot.gammaToCandidates(key, candidates):
			if preference in remainingCandidates:
				assigned = Fraction('0')
				isExhausted = False
				for ballot in group:
					assigned += ballot.value
					preference.ctvv += ballot.value
					preference.ballots.append(ballot)
				
				print("---- Assigned {:.2f} votes to {} via {}".format(float(assigned), preference.name, key))
				break
		if isExhausted:
			for ballot in group:
				exhausted += ballot.value
				ballot.value = Fraction('0')
			print("---- Exhausted {:.2f} votes via {}".format(float(exhausted), key))
	
	return exhausted

def totalVote(candidates):
	tv = Fraction('0')
	for candidate in candidates:
		tv += candidate.ctvv
	return tv

# Return the candidate to transfer votes to
def surplusTransfer(preferences, fromCandidate, provisionallyElected, remainingCandidates):
	beginPreference = preferences.index(fromCandidate)
	for index in range(beginPreference + 1, len(preferences)):
		preference = preferences[index]
		if preference in remainingCandidates and preference not in provisionallyElected:
			return preference
	return False

def printVotes(remainingCandidates, provisionallyElected):
	print()
	for candidate in remainingCandidates:
		print("    {}{}: {:.2f}".format("*" if candidate in provisionallyElected else " ", candidate.name, float(candidate.ctvv)))
	print()

def countVotes(ballots, candidates):
	count = 1
	remainingCandidates = candidates[:]
	while True:
		print()
		print("== COUNT {}".format(count))
		provisionallyElected = []
		
		resetCount(ballots, candidates)
		exhausted = distributePreferences(ballots, remainingCandidates)
		
		printVotes(remainingCandidates, provisionallyElected)
		
		quota = totalVote(candidates) / (numSeats + 1)
		#quota = (totalVote(candidates) / (numSeats + 1) + 1).__floor__()
		print("---- Exhausted: {:.2f}".format(float(exhausted)))
		print("---- Quota: {:.2f}".format(float(quota)))
		
		remainingCandidates = sorted(remainingCandidates, key=lambda k: k.ctvv, reverse=True)
		for candidate in remainingCandidates:
			if candidates not in provisionallyElected and candidate.ctvv > quota:
			#if candidates not in provisionallyElected and candidate.ctvv >= quota:
				print("**** {} provisionally elected".format(candidate.name))
				provisionallyElected.append(candidate)
		
		if len(provisionallyElected) == numSeats:
			return provisionallyElected, exhausted
		
		mostVotesElected = sorted(provisionallyElected, key=lambda k: k.ctvv, reverse=True)
		# While surpluses remain
		while mostVotesElected and mostVotesElected[0].ctvv > quota:
			for candidate in mostVotesElected:
				if candidate.ctvv > quota:
					multiplier = (candidate.ctvv - quota) / candidate.ctvv
					print("---- Transferring surplus from {} at value {:.2f}".format(candidate.name, float(multiplier)))
					
					for key, group in itertools.groupby(sorted(candidate.ballots, key=lambda k: k.gamma), lambda k: k.gamma):
						transferTo = surplusTransfer(Ballot.gammaToCandidates(key, candidates), candidate, provisionallyElected, remainingCandidates)
						if transferTo == False:
							transferred = Fraction('0')
							for ballot in group:
								transferred += ballot.value
							exhausted += transferred
							print("---- Exhausted {:.2f} votes via {}".format(float(transferred), key))
						else:
							transferred = Fraction('0')
							for ballot in group:
								transferred += ballot.value
								ballot.value *= multiplier
								transferTo.ctvv += ballot.value
								transferTo.ballots.append(ballot)
							print("---- Transferred {:.2f} votes to {} via {}".format(float(transferred), transferTo.name, key))
					
					candidate.ctvv = quota
					
					printVotes(remainingCandidates, provisionallyElected)
					
					for candidate in remainingCandidates:
						if candidate not in provisionallyElected and candidate.ctvv > quota:
							print("**** {} provisionally elected".format(candidate.name))
							provisionallyElected.append(candidate)
					
					if len(provisionallyElected) == numSeats:
						return provisionallyElected, exhausted
			mostVotesElected = sorted(provisionallyElected, key=lambda k: k.ctvv, reverse=True)
		
		# Bulk exclude as many candidates as possible
		candidatesToExclude = []
		votesToExclude = Fraction('0')
		
		remainingCandidates.sort(key=lambda k: k.ctvv)
		grouped = [(x, list(y)) for x, y in itertools.groupby(remainingCandidates, lambda k: k.ctvv)] # ily python
		for i in range(0, len(grouped)):
			key, group = grouped[i]
			
			# Would the total number of votes to exclude geq the next lowest candidate?
			if len(grouped) > i + 1 and votesToExclude + totalVote(group) >= float(grouped[i + 1][0]):
				break
			
			# Would the total number of votes to exclude allow a candidate to reach the quota?
			lowestShortfall = float("inf")
			for candidate in remainingCandidates:
				if candidate not in provisionallyElected and (quota - candidate.ctvv < lowestShortfall):
					lowestShortfall = quota - candidate.ctvv
			if votesToExclude + totalVote(group) >= lowestShortfall:
				break
			
			# Still here? Okay!
			candidatesToExclude.extend(group)
			votesToExclude += totalVote(group)
		
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
		
		# Uncomment this to enable bulk election (does not allow for the computation of ranked winners)
		#if len(remainingCandidates) == numSeats:
		#	for candidate in remainingCandidates:
		#		if candidate not in provisionallyElected:
		#			print("**** {} provisionally elected".format(candidate.name))
		#			provisionallyElected.append(candidate)
		#	return provisionallyElected, exhausted
		
		count += 1

with open(electionIn, 'r') as electionFile:
	election = json.load(electionFile)
	
	candidates = []
	for candidate in election["questions"][question]["answers"]:
		candidates.append(Candidate(candidate.split("/")[0])) # Just want the name
	
	with open(resultIn, 'r') as resultFile:
		results = json.load(resultFile)
		
		ballots = []
		for result in results[question]:
			ballots.append(Ballot(result, candidates))

provisionallyElected, exhausted = countVotes(ballots, candidates)
print()
print("== TALLY COMPLETE")
print()
print("The winners are, in order of election:")

print()
for candidate in provisionallyElected:
	print("     {}".format(candidate.name))
print()

print("---- Exhausted: {:.2f}".format(float(exhausted)))

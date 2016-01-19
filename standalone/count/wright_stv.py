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

electionIn = sys.argv[1]
resultIn = sys.argv[2]
question = int(sys.argv[3])
numSeats = int(sys.argv[4])

class Ballot:
	def __init__(self, gamma, candidates):
		self.gamma = gamma
		self.preferences = Ballot.gammaToCandidates(gamma, candidates)
		self.value = 1
	
	def gammaToCandidates(gamma, candidates):
		return [candidates[x] for x in utils.gamma_decode(gamma, len(candidates))]

class Candidate:
	def __init__(self, name):
		self.name = name
		self.ctvv = 0
		self.ballots = []
	
	def shortCtvv(self):
		return "{:.5f}".format(self.ctvv)

def resetCount(ballots, candidates):
	for ballot in ballots:
		ballot.value = 1
	for candidate in candidates:
		candidate.ctvv = 0
		candidate.ballots.clear()

def distributePreferences(ballots, remainingCandidates):
	exhausted = 0
	
	for key, group in itertools.groupby(sorted(ballots, key=lambda k: k.gamma), lambda k: k.gamma):
		isExhausted = True
		for preference in Ballot.gammaToCandidates(key, candidates):
			if preference in remainingCandidates:
				assigned = 0
				isExhausted = False
				for ballot in group:
					assigned += ballot.value
					preference.ctvv += ballot.value
					preference.ballots.append(ballot)
				
				print("---- Assigned {} votes to {} via {}".format(assigned, preference.name, key))
				break
		if isExhausted:
			for ballot in group:
				exhausted += ballot.value
				ballot.value = 0
			print("---- Exhausted {} votes via {}".format(exhausted, key))
	
	return exhausted

def totalVote(candidates):
	tv = 0
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
		print("    {}{}: {}".format("*" if candidate in provisionallyElected else " ", candidate.name, candidate.ctvv))
	print()

def countVotes(ballots, candidates):
	count = 1
	remainingCandidates = candidates[:]
	while True:
		print()
		print("== COUNT {}".format(count))
		exhausted = 0
		provisionallyElected = []
		
		resetCount(ballots, candidates)
		exhausted += distributePreferences(ballots, remainingCandidates)
		
		printVotes(remainingCandidates, provisionallyElected)
		
		quota = totalVote(candidates) / (numSeats + 1)
		print("---- Exhausted: {}".format(exhausted))
		print("---- Quota: {}".format(quota))
		
		for candidate in remainingCandidates:
			if candidate.ctvv > quota:
				print("**** {} provisionally elected".format(candidate.name))
				provisionallyElected.append(candidate)
		
		if len(provisionallyElected) == numSeats:
			return provisionallyElected
		
		mostVotesElected = sorted(provisionallyElected, key=lambda k: k.ctvv, reverse=True)
		
		# While surpluses remain
		while mostVotesElected and mostVotesElected[0].ctvv > quota:
			for candidate in mostVotesElected:
				if candidate.ctvv > quota:
					multiplier = (candidate.ctvv - quota) / candidate.ctvv
					
					for key, group in itertools.groupby(sorted(candidate.ballots, key=lambda k: k.gamma), lambda k: k.gamma):
						transferTo = surplusTransfer(Ballot.gammaToCandidates(key, candidates), candidate, provisionallyElected, remainingCandidates)
						if transferTo == False:
							for ballot in group:
								exhausted += ballot.value
						else:
							transferred = 0
							for ballot in group:
								transferred += ballot.value
								ballot.value *= multiplier
								transferTo.ctvv += ballot.value
								transferTo.ballots.append(ballot)
							print("---- Transferred {} votes from {} to {} at value {} via {}".format(transferred, candidate.name, transferTo.name, multiplier, key))
					
					candidate.ctvv = quota
					
					printVotes(remainingCandidates, provisionallyElected)
					
					for candidate in remainingCandidates:
						if candidate.ctvv > quota:
							print("**** {} provisionally elected".format(candidate.name))
							provisionallyElected.append(candidate)
					
					if len(provisionallyElected) == numSeats:
						return provisionallyElected
			mostVotesElected = sorted(provisionallyElected, key=lambda k: k.ctvv, reverse=True)
		
		remainingCandidates.sort(key=lambda k: k.ctvv)
		
		toExclude = 0
		
		# Check for a tie
		if len(remainingCandidates) > 1 and remainingCandidates[0].shortCtvv() == remainingCandidates[1].shortCtvv():
			print("---- There is a tie for last place:")
			for i in range(0, len(remainingCandidates)):
				if remainingCandidates[i].shortCtvv() == remainingCandidates[0].shortCtvv():
					print("     {}. {}".format(i, remainingCandidates[i].name))
			print("---- Which candidate to exclude?")
			toExclude = int(input())
		
		print("---- Excluding {}".format(remainingCandidates[toExclude].name))
		remainingCandidates.pop(toExclude)
		
		if len(remainingCandidates) == numSeats:
			for candidate in remainingCandidates:
				if candidate not in provisionallyElected:
					print("**** {} provisionally elected".format(candidate.name))
					provisionallyElected.append(candidate)
			return provisionallyElected
		
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

provisionallyElected = countVotes(ballots, candidates)
print()
print("== TALLY COMPLETE")
print()
print("The winners are, in order of election:")

resetCount(ballots, provisionallyElected)
exhausted = distributePreferences(ballots, provisionallyElected)
provisionallyElected.sort(key=lambda k: k.ctvv, reverse=True)

printVotes(provisionallyElected, provisionallyElected)

print("---- Exhausted: {}".format(exhausted))

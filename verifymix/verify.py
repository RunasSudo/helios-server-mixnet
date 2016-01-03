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

from mixnet.Ciphertext import Ciphertext
from mixnet.CiphertextCollection import CiphertextCollection
from mixnet.EGCryptoSystem import EGCryptoSystem
from mixnet.PrivateKey import PrivateKey
from mixnet.PublicKey import PublicKey
from mixnet.ShufflingProof import ShufflingProof

import hashlib, itertools, json, sys, urllib2

electionUrl = sys.argv[1].rstrip("/")
NUM_BITS = 2048 # TODO: Actually detect this

class VerificationException(Exception):
	pass

class statusCheck:
	def __init__(self, status):
		print(status, end="")
	def __enter__(self):
		return
	def __exit__(self, type, value, traceback):
		if value:
			print(": FAIL")
		else:
			print(": OK")

with statusCheck("Downloading election data"):
	# Election
	election = json.load(urllib2.urlopen(electionUrl))
	
	cryptosystem = EGCryptoSystem.load(NUM_BITS, long(election["public_key"]["p"]), int(election["public_key"]["g"])) # The generator might be a long if it's big? I don't know.
	pk = PublicKey(cryptosystem, long(election["public_key"]["y"]))
	
	# Ballots
	ballots = []
	ballotList = json.load(urllib2.urlopen(electionUrl + "/ballots"))
	for ballotInfo in ballotList:
		ballot = json.load(urllib2.urlopen(electionUrl + "/ballots/" + ballotInfo["voter_uuid"] + "/last"))
		ballots.append(ballot)
	
	# Results
	results = json.load(urllib2.urlopen(electionUrl + "/result"))
	
	# Mixes & Proofs
	mixnets = []
	numMixnets = json.load(urllib2.urlopen(electionUrl + "/mixnets"))
	for i in xrange(0, numMixnets):
		mixedAnswers = json.load(urllib2.urlopen(electionUrl + "/mixnets/" + str(i) + "/answers"))
		shufflingProof = json.load(urllib2.urlopen(electionUrl + "/mixnets/" + str(i) + "/proof"))
		mixnets.append((mixedAnswers, shufflingProof))
	
	assert(numMixnets == 1) # TODO: Multiple mixnets
	
	# Trustees
	trustees = json.load(urllib2.urlopen(electionUrl + "/trustees"))
	assert(len(trustees) == 1) # TODO: Multiple trustees

with statusCheck("Verifying mix"):
	proof = ShufflingProof.from_dict(mixnets[0][1], pk, NUM_BITS)
	
	orig = CiphertextCollection(pk)
	for ballot in reversed(ballots):
		ciphertext = Ciphertext(NUM_BITS, orig._pk_fingerprint)
		
		ciphertext.append(long(ballot["vote"]["answers"][0]["choices"][0]["alpha"]), long(ballot["vote"]["answers"][0]["choices"][0]["beta"]))
		
		orig.add_ciphertext(ciphertext)
	
	shuf = CiphertextCollection(pk)
	for ballot in mixedAnswers["answers"]:
		ciphertext = Ciphertext(NUM_BITS, shuf._pk_fingerprint)
		
		ciphertext.append(long(ballot["choice"]["alpha"]), long(ballot["choice"]["beta"]))
		
		shuf.add_ciphertext(ciphertext)
	
	# Check the challenge ourselves to provide a more informative error message
	expected_challenge = proof._generate_challenge(orig, shuf)
	if proof._challenge != expected_challenge:
		raise VerificationException("Challenge is wrong")
	
	# Do the maths
	if not proof.verify(orig, shuf):
		raise VerificationException("Shuffle failed to prove")

with statusCheck("Verifying decryption proofs"):
	for ballot, result, factor, proof in itertools.izip(mixedAnswers["answers"], results[0], trustees[0]["decryption_factors"][0], trustees[0]["decryption_proofs"][0]):
		# TODO: Check the factors, whatever those are...
		
		# Check the challenge
		C = long(proof["challenge"])
		expected_challenge = int(hashlib.sha1(proof["commitment"]["A"] + "," + proof["commitment"]["B"]).hexdigest(), 16)
		if C != expected_challenge:
			raise VerificationException("Challenge is wrong")
		
		# Do the maths
		T = long(proof["response"])
		P = cryptosystem.get_prime()
		
		GT = pow(cryptosystem.get_generator(), T, P)
		AYC = (long(proof["commitment"]["A"]) * pow(pk._key, C, P)) % P
		if not GT == AYC:
			raise VerificationException("g^t != Ay^c (mod p)")
		
		AT = pow(long(ballot["choice"]["alpha"]), T, P)
		BM = (long(ballot["choice"]["beta"]) * pow(result + 1, P - 2, P)) % P
		BBMC = (long(proof["commitment"]["B"]) * pow(BM, C, P)) % P
		
		if not AT == BBMC:
			raise VerificationException("alpha^t != B(beta/m)^c (mod p)")

print("The election has passed validation.")

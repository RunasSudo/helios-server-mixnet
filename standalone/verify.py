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

from mixnet.threshold.PartialDecryption import PartialDecryption, PartialDecryptionBlock, PartialDecryptionBlockProof
from mixnet.threshold.ThresholdDecryptionCombinator import ThresholdDecryptionCombinator
from mixnet.threshold.ThresholdEncryptionCommitment import ThresholdEncryptionCommitment
from mixnet.threshold.ThresholdEncryptionSetUp import ThresholdEncryptionSetUp
from mixnet.threshold.ThresholdPublicKey import ThresholdPublicKey

import hashlib, itertools, json, math, sys, urllib2

electionUrl = sys.argv[1].rstrip("/")

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
	numQuestions = len(election['questions'])
	
	nbits = ((int(math.log(long(election["public_key"]["p"]), 2)) - 1) & ~255) + 256
	cryptosystem = EGCryptoSystem.load(nbits, long(election["public_key"]["p"]), int(election["public_key"]["g"])) # The generator might be a long if it's big? I don't know.
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
	
	# Trustees
	trustees = json.load(urllib2.urlopen(electionUrl + "/trustees"))
	trusteeThreshold = int(election['trustee_threshold'])

# Verify mixes
for i in xrange(0, numMixnets):
	index = numMixnets - i - 1
	for q in xrange(0, numQuestions):
		with statusCheck("Verifying mix " + str(index) + " question " + str(q)):
			proof = ShufflingProof.from_dict(mixnets[index][1][q], pk, nbits)
			
			orig = CiphertextCollection(pk)
			if i == 0:
				for ballot in ballots:
					ciphertext = Ciphertext(nbits, orig._pk_fingerprint)
					ciphertext.append(long(ballot["vote"]["answers"][q]["choices"][0]["alpha"]), long(ballot["vote"]["answers"][q]["choices"][0]["beta"]))
					orig.add_ciphertext(ciphertext)
			else:
				for ballot in mixnets[index + 1][0][q]["answers"]:
					ciphertext = Ciphertext(nbits, orig._pk_fingerprint)
					ciphertext.append(long(ballot["choice"]["alpha"]), long(ballot["choice"]["beta"]))
					orig.add_ciphertext(ciphertext)
			
			shuf = CiphertextCollection(pk)
			for ballot in mixnets[index][0][q]["answers"]:
				ciphertext = Ciphertext(nbits, shuf._pk_fingerprint)
				ciphertext.append(long(ballot["choice"]["alpha"]), long(ballot["choice"]["beta"]))
				shuf.add_ciphertext(ciphertext)
			
			# Check the challenge ourselves to provide a more informative error message
			expected_challenge = proof._generate_challenge(orig, shuf)
			if proof._challenge != expected_challenge:
				raise VerificationException("Challenge is wrong")
			
			# Do the maths
			if not proof.verify(orig, shuf):
				raise VerificationException("Shuffle failed to prove")

# Verify decryptions
if trusteeThreshold <= 0:
	for q in xrange(0, numQuestions):
		ballots = mixnets[0][0][q]["answers"]
		for i in xrange(0, len(ballots)):
			print("Verifying decryptions for question " + str(q) + " ballot " + str(i))
			ballot = ballots[i]
			result = long(results[q][i])
			decryption_factor_combination = 1L
			
			P = cryptosystem.get_prime()
			
			for j in xrange(0, len(trustees)):
				with statusCheck("Verifying decryption by trustee " + str(j)):
					factor = long(trustees[j]["decryption_factors"][q][i])
					proof = trustees[j]["decryption_proofs"][q][i]
					
					# Check the challenge
					C = long(proof["challenge"])
					expected_challenge = int(hashlib.sha1(proof["commitment"]["A"] + "," + proof["commitment"]["B"]).hexdigest(), 16)
					if C != expected_challenge:
						raise VerificationException("Challenge is wrong")
					
					# Do the maths
					T = long(proof["response"])
					
					GT = pow(cryptosystem.get_generator(), T, P)
					AYC = (long(proof["commitment"]["A"]) * pow(long(trustees[j]["public_key"]["y"]), C, P)) % P
					if GT != AYC:
						raise VerificationException("g^t != Ay^c (mod p)")
					
					AT = pow(long(ballot["choice"]["alpha"]), T, P)
					BFC = (long(proof["commitment"]["B"]) * pow(factor, C, P)) % P
					
					if AT != BFC:
						raise VerificationException("alpha^t != B(factor)^c (mod p)")
					
					decryption_factor_combination *= factor
			
			# Check the claimed decryption
			decryption_factor_combination *= result
			
			if (decryption_factor_combination % P) != (long(ballot["choice"]["beta"]) % P):
				print("FAIL")
				raise VerificationException("Claimed plaintext doesn't match decryption factors")
else:
	# We need a ThresholdPublicKey
	tesu = ThresholdEncryptionSetUp(cryptosystem, len(trustees), trusteeThreshold)
	for trustee in xrange(0, len(trustees)):
		commitment = trustees[trustee]['commitment']
		
		def to_ciphertext(idx):
			ciphertext = Ciphertext(nbits, trustees[idx]['public_key_hash'])
			
			for i in xrange(0, len(commitment['encrypted_partial_private_keys'][idx])):
				ciphertext.append(long(commitment['encrypted_partial_private_keys'][idx][i]['alpha']), long(commitment['encrypted_partial_private_keys'][idx][i]['beta']))
			
			return ciphertext
		
		tesu.add_trustee_commitment(trustee, ThresholdEncryptionCommitment(
			cryptosystem, len(trustees), trusteeThreshold,
			[long(x) for x in commitment['public_coefficients']],
			[to_ciphertext(x) for x in xrange(0, len(commitment['encrypted_partial_private_keys']))]
		))
	tpk = tesu.generate_public_key()
	
	for q in xrange(0, numQuestions):
		ballots = mixnets[0][0][q]["answers"]
		for i in xrange(0, len(ballots)):
			print("Verifying decryptions for question " + str(q) + " ballot " + str(i))
			ballot = ballots[i]
			result = long(results[q][i])
			
			ciphertext = Ciphertext(cryptosystem.get_nbits(), tpk.get_fingerprint())
			ciphertext.append(long(ballot["choice"]["alpha"]), long(ballot["choice"]["beta"]))
			combinator = ThresholdDecryptionCombinator(tpk, ciphertext, len(trustees), trusteeThreshold)
			
			for j in xrange(0, len(trustees)):
				with statusCheck("Verifying decryption by trustee " + str(j)):
					factor = long(trustees[j]["decryption_factors"][q][i])
					proof = trustees[j]["decryption_proofs"][q][i]
					
					pd = PartialDecryption(cryptosystem.get_nbits())
					pdbp = PartialDecryptionBlockProof(
						long(proof['challenge']),
						long(proof['commitment']['A']),
						long(proof['commitment']['B']),
						long(proof['response'])
					)
					pdb = PartialDecryptionBlock(factor, pdbp)
					pd.add_partial_decryption_block(pdb)
					
					try:
						combinator.add_partial_decryption(j, pd) # this verifies the decryption
					except:
						raise VerificationException("Partial decryption doesn't verify")
			
			bitstream = combinator.decrypt_to_bitstream()
			bitstream.seek(0)
			if bitstream.get_num(bitstream.get_length()) != result:
				print("FAIL")
				raise VerificationException("Claimed plaintext doesn't match decryption factors")

print("The election has passed validation. The results are:")
print(results)

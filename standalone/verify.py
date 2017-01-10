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

import argparse
parser = argparse.ArgumentParser(description="Verify a helios-server-mixnet election.")

parser.add_argument("location", help="URL or path to the election")
parser.add_argument("--type", choices=["local", "remote"], default="local")
parser.add_argument("--uuid", help="Manually specify the UUID of the election if local")
args = parser.parse_args()

args.location = args.location.rstrip("/")
if args.uuid is None:
	args.uuid = args.location.split("/")[-1]

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

import hashlib, itertools, json, math, urllib2, sys, traceback

def get_file(loc_remote, loc_local=None):
	global args
	if args.type == "local":
		if loc_local is None:
			loc_local = "/" + args.uuid + loc_remote + ".json"
		with open(args.location + loc_local, "r") as f:
			return f.read()
	else:
		return urllib2.urlopen(args.location + loc_remote).read()

verificationProblems = []

class statusCheck:
	def __init__(self, status, parent=None):
		self.problems = []
		self.status = status
		self.parent = parent
		self.onLinePart = True
		
		if self.parent and self.parent.onLinePart:
			print() # Finish parent status line
			self.parent.onLinePart = False
		print(status, end="")
		sys.stdout.flush()
	def __enter__(self):
		return self
	def __exit__(self, type, value, tb):
		if value:
			self.fail(str(value))
			traceback.print_tb(tb)
		
		if len(self.problems) > 0:
			print(self.status + ": FAIL") # New line
		else:
			if self.onLinePart:
				print(": OK") # Finish status line
			else:
				print(self.status + ": OK") # New line
	
	def fail(self, message, propagated=False):
		if not propagated:
			if self.onLinePart:
				print() # Finish status line
				self.onLinePart = False
			print(message)
			verificationProblems.append(self.status + ': ' + message)
		self.problems.append(message)
		if self.parent:
			self.parent.fail(message, True)

with statusCheck("Getting election data") as sc:
	# Election
	election = json.loads(get_file(""))
	numQuestions = len(election['questions'])
	
	nbits = ((int(math.log(long(election["public_key"]["p"]), 2)) - 1) & ~255) + 256
	cryptosystem = EGCryptoSystem.load(nbits, long(election["public_key"]["p"]), int(election["public_key"]["g"])) # The generator might be a long if it's big? I don't know.
	pk = PublicKey(cryptosystem, long(election["public_key"]["y"]))
	
	# Ballots
	ballots = json.loads(get_file("/ballots"))
	
	# Results
	results = json.loads(get_file("/result"))
	
	# Mixes & Proofs
	mixnets = []
	numMixnets = len(json.loads(get_file("/mixnets")))
	for i in xrange(0, numMixnets):
		mixedAnswers = json.loads(get_file("/mixnets/" + str(i) + "/answers"))
		shufflingProof = json.loads(get_file("/mixnets/" + str(i) + "/proof"))
		mixnets.append((mixedAnswers, shufflingProof))
	
	# Trustees
	trustees = json.loads(get_file("/trustees"))
	trusteeThreshold = int(election['trustee_threshold'])

# Verify mixes
for i in xrange(0, numMixnets):
	index = numMixnets - i - 1
	with statusCheck("Verifying mix " + str(index)) as sc:
		for q in xrange(0, numQuestions):
			with statusCheck("Verifying mix " + str(index) + " question " + str(q), sc) as sc2:
				proof = ShufflingProof.from_dict(mixnets[index][1][q], pk, nbits)
				
				orig = CiphertextCollection(pk)
				if i == 0:
					for ballot in ballots:
						ciphertext = Ciphertext(nbits, orig._pk_fingerprint)
						for block in ballot["vote"]["answers"][q]["choices"]:
							ciphertext.append(long(block["alpha"]), long(block["beta"]))
						orig.add_ciphertext(ciphertext)
				else:
					for ballot in mixnets[index + 1][0][q]["answers"]:
						ciphertext = Ciphertext(nbits, orig._pk_fingerprint)
						for block in ballot["choices"]:
							ciphertext.append(long(block["alpha"]), long(block["beta"]))
						orig.add_ciphertext(ciphertext)
				
				shuf = CiphertextCollection(pk)
				for ballot in mixnets[index][0][q]["answers"]:
					ciphertext = Ciphertext(nbits, shuf._pk_fingerprint)
					for block in ballot["choices"]:
						ciphertext.append(long(block["alpha"]), long(block["beta"]))
					shuf.add_ciphertext(ciphertext)
				
				# Check the challenge ourselves to provide a more informative error message
				expected_challenge = proof._generate_challenge(orig, shuf)
				if proof._challenge != expected_challenge:
					sc2.fail("Challenge is wrong")
				
				# Do the maths
				if not proof.verify(orig, shuf):
					sc2.fail("Shuffle failed to prove")

# Verify decryptions
if trusteeThreshold <= 0:
	for q in xrange(0, numQuestions):
		with statusCheck("Verifying decryptions for question " + str(index)) as sc:
			ballots = mixnets[0][0][q]["answers"]
			for i in xrange(0, len(ballots)):
				with statusCheck("Verifying decryptions for question " + str(q) + " ballot " + str(i), sc) as sc2:
					ballot = ballots[i]
					result = [long(x) for x in results[q][i]]
					
					for block in xrange(0, len(ballot["choices"])):
						with statusCheck("Verifying decryptions for question " + str(q) + " ballot " + str(i) + " block " + str(block), sc2) as sc3:
							decryption_factor_combination = 1L
							
							P = cryptosystem.get_prime()
							
							for j in xrange(0, len(trustees)):
								with statusCheck("Verifying decryptions for question " + str(q) + " ballot " + str(i) + " block " + str(block) + " by trustee " + str(j), sc3) as sc4:
									factor = long(trustees[j]["decryption_factors"][q][i][block])
									proof = trustees[j]["decryption_proofs"][q][i][block]
									
									# Check the challenge
									C = long(proof["challenge"])
									expected_challenge = int(hashlib.sha1(proof["commitment"]["A"] + "," + proof["commitment"]["B"]).hexdigest(), 16)
									if C != expected_challenge:
										sc4.fail("Challenge is wrong")
									
									# Do the maths
									T = long(proof["response"])
									
									GT = pow(cryptosystem.get_generator(), T, P)
									AYC = (long(proof["commitment"]["A"]) * pow(long(trustees[j]["public_key"]["y"]), C, P)) % P
									if GT != AYC:
										sc4.fail("g^t != Ay^c (mod p)")
									
									AT = pow(long(ballot["choices"][block]["alpha"]), T, P)
									BFC = (long(proof["commitment"]["B"]) * pow(factor, C, P)) % P
			
									if AT != BFC:
										sc4.fail("alpha^t != B(factor)^c (mod p)")
									
									decryption_factor_combination *= factor
							
							# Check the claimed decryption
							decryption_factor_combination *= result[block]
							
							if (decryption_factor_combination % P) != (long(ballot["choices"][block]["beta"]) % P):
								sc3.fail("Claimed plaintext doesn't match decryption factors")
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
		with statusCheck("Verifying decryptions for question " + str(q)) as sc:
			ballots = mixnets[0][0][q]["answers"]
			for i in xrange(0, len(ballots)):
				with statusCheck("Verifying decryptions for question " + str(q) + " ballot " + str(i), sc) as sc2:
					ballot = ballots[i]
					result = long(results[q][i])
					
					ciphertext = Ciphertext(cryptosystem.get_nbits(), tpk.get_fingerprint())
					ciphertext.append(long(ballot["choice"]["alpha"]), long(ballot["choice"]["beta"]))
					combinator = ThresholdDecryptionCombinator(tpk, ciphertext, len(trustees), trusteeThreshold)
					
					for j in xrange(0, len(trustees)):
						with statusCheck("Verifying decryptions for question " + str(q) + " ballot " + str(i) + " by trustee " + str(j), sc2) as sc3:
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
								sc3.fail("Partial decryption doesn't verify")
					
					bitstream = combinator.decrypt_to_bitstream()
					bitstream.seek(0)
					if bitstream.get_num(bitstream.get_length()) != result:
						sc2.fail("Claimed plaintext doesn't match decryption factors")

if len(verificationProblems) == 0:
	print("The election has passed validation. The results are:")
	print(results)
else:
	print("The election failed validation. The problems encountered were:")
	for problem in verificationProblems:
		print(problem)

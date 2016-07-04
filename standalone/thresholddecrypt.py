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
from mixnet.EGCryptoSystem import EGCryptoSystem
from mixnet.PrivateKey import PrivateKey
from mixnet.PublicKey import PublicKey
from mixnet.threshold.ThresholdEncryptionCommitment import ThresholdEncryptionCommitment
from mixnet.threshold.ThresholdEncryptionSetUp import ThresholdEncryptionSetUp

import json, math, sys

electionIn = sys.argv[1]
trusteesIn = sys.argv[2]
ballotsIn = sys.argv[3]
secretIn = sys.argv[4]
number = int(sys.argv[5]) # zero-indexed

with open(electionIn, 'r') as electionFile:
	election = json.load(electionFile)
	
	nbits = ((int(math.log(long(election["public_key"]["p"]), 2)) - 1) & ~255) + 256
	cryptosystem = EGCryptoSystem.load(nbits, long(election["public_key"]["p"]), int(election["public_key"]["g"])) # The generator might be a long if it's big? I don't know.
	
	public_key = PublicKey(cryptosystem, long(election["public_key"]["y"]))
	pkf = public_key.get_fingerprint()

with open(trusteesIn, 'r') as trusteesFile:
	trustees = json.load(trusteesFile)

with open(ballotsIn, 'r') as ballotsFile:
	ballots = json.load(ballotsFile)

with open(secretIn, 'r') as secretFile:
	secret_json = json.load(secretFile)
	
	secret = PrivateKey(cryptosystem, long(secret_json["x"]))

setup = ThresholdEncryptionSetUp(cryptosystem, len(trustees), election["trustee_threshold"])

# Add trustee commitments
for trustee in xrange(0, len(trustees)):
	def to_ciphertext(idx):
		ciphertext = Ciphertext(nbits, PublicKey(cryptosystem, long(trustees[idx]["public_key"]["y"])).get_fingerprint())
		
		for i in xrange(0, len(trustees[trustee]["commitment"]["encrypted_partial_private_keys"][idx])):
			ciphertext.append(long(trustees[trustee]["commitment"]["encrypted_partial_private_keys"][idx][i]["alpha"]), long(trustees[trustee]["commitment"]["encrypted_partial_private_keys"][idx][i]["beta"]))
		
		return ciphertext
	
	setup.add_trustee_commitment(trustee, ThresholdEncryptionCommitment(
		cryptosystem, len(trustees), election["trustee_threshold"],
		[long(x) for x in trustees[trustee]["commitment"]["public_coefficients"]],
		[to_ciphertext(idx) for idx in range(0, len(trustees))]
	))

threshold_key = setup.generate_private_key(number, secret)

partial_decryptions = []

# Perform partial decryptions
for question in ballots:
	partial_decryption_q = []
	
	for ballot in question["answers"]:
		ciphertext = Ciphertext(nbits, pkf)
		ciphertext.append(long(ballot["choice"]["alpha"]), long(ballot["choice"]["beta"]))
		
		partial_decryption = threshold_key.generate_partial_decryption(ciphertext)
		
		partial_decryption_q.append(partial_decryption)
	
	partial_decryptions.append(partial_decryption_q)

# Convert to Helios format
decryption_factors = [[str(decryption[0].value) for decryption in question] for question in partial_decryptions]
decryption_proofs = [[{
	"challenge": str(decryption[0].proof.c),
	"commitment": {"A": str(decryption[0].proof.a), "B": str(decryption[0].proof.b)},
	"response": str(decryption[0].proof.t)
} for decryption in question] for question in partial_decryptions]

print(json.dumps({
	"decryption_factors": decryption_factors,
	"decryption_proofs": decryption_proofs
}))

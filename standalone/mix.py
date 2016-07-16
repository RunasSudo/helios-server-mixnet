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

import hashlib, itertools, json, math, sys, urllib2

dataIn = sys.argv[1]
shuffleOut = sys.argv[2]
proofOut = sys.argv[3]

with open(dataIn, 'r') as dataFile:
	data = json.load(dataFile)

nbits = ((int(math.log(long(data["public_key"]["p"]), 2)) - 1) & ~255) + 256
cryptosystem = EGCryptoSystem.load(nbits, long(data["public_key"]["p"]), int(data["public_key"]["g"])) # The generator might be a long if it's big? I don't know.
pk = PublicKey(cryptosystem, long(data["public_key"]["y"]))

ballots = data["answers"]
shufs_list = []
proofs_list = []

def shuffleQuestion(question):
	orig = CiphertextCollection(pk)
	for ballot in ballots[question]:
		ciphertext = Ciphertext(nbits, orig._pk_fingerprint)
		
		for choice in ballot["choices"]:
			ciphertext.append(long(choice["alpha"]), long(choice["beta"]))
		
		orig.add_ciphertext(ciphertext)
	
	print("Shuffling answers for question " + str(question))
	shuf, proof = orig.shuffle_with_proof()
	
	shufs_list.append(shuf.to_dict())
	proofs_list.append(proof.to_dict())
	
	print("Shuffle complete for question " + str(question))

if len(sys.argv) > 4:
	shuffleQuestion(int(sys.argv[4]))
else:
	for question in xrange(0, len(ballots)):
		shuffleQuestion(question)

print("Writing results to file")
with open(shuffleOut, 'w') as shuffleFile:
	json.dump(shufs_list, shuffleFile)
with open(proofOut, 'w') as proofFile:
	json.dump(proofs_list, proofFile)

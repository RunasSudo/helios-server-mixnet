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

from mixnet.EGCryptoSystem import EGCryptoSystem
from mixnet.PublicKey import PublicKey
from mixnet.threshold.ThresholdEncryptionSetUp import ThresholdEncryptionSetUp

import json, math, sys

electionIn = sys.argv[1]
trusteesIn = sys.argv[2]

with open(electionIn, 'r') as electionFile:
	election = json.load(electionFile)

with open(trusteesIn, 'r') as trusteesFile:
	trustees = json.load(trusteesFile)
	
	nbits = ((int(math.log(long(trustees[0]["public_key"]["p"]), 2)) - 1) & ~255) + 256
	cryptosystem = EGCryptoSystem.load(nbits, long(trustees[0]["public_key"]["p"]), int(trustees[0]["public_key"]["g"])) # The generator might be a long if it's big? I don't know.

setup = ThresholdEncryptionSetUp(cryptosystem, len(trustees), election["trustee_threshold"])

# Add trustee public keys
for i in xrange(0, len(trustees)):
	pk = PublicKey(cryptosystem, long(trustees[i]["public_key"]["y"]))
	setup.add_trustee_public_key(i, pk)

commitment = setup.generate_commitment()

print(json.dumps({
	"public_coefficients": [str(x) for x in commitment.public_coefficients],
	"encrypted_partial_private_keys": [
		# The partial private key is too big for one single (a, b) pair
		[{"alpha": str(x.gamma[i]), "beta": str(x.delta[i])} for i in xrange(0, x.get_length())]
		for x in commitment.encrypted_partial_private_keys
	]
}))

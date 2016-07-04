# Helios Election System with mixnet support

Helios is an end-to-end verifiable voting system.

This is a fork of [Ben Adida's Helios server](https://github.com/benadida/helios-server), with support for mixnets using code pulled in from [Zeus](https://github.com/grnet/zeus), and support for threshold decryption, but without the other changes made in Zeus, and with some other minor changes.

## Features

* This fork produces a tally of the ballots cast, like Zeus. This allows it to be used in voting systems other than approval voting (which is supported by Helios), since the vote tally can be fed to any other system that actually produces the election results.
  * A drag-and-drop interface for STV is implemented, and a standalone counter.
* Optional reddit authentication support.
* Improved support for password authentication.
* Group voting ticket support.
  * Input candidates using the format `Name/Party/1`, where the candidates are sorted within the GVT by the number (can be a decimal).

### A word on security

This implementation produces 80 shadow mixes for each shuffling proof, in accordance with the [original Helios paper](https://www.usenix.org/legacy/event/sec08/tech/full_papers/adida/adida.pdf). This is less than its inspiration, [Josh Benaloh's paper](https://www.usenix.org/legacy/event/evt06/tech/full_papers/benaloh/benaloh.pdf) (which recommends 100), and Zeus (which uses 128 by default). You may want to increase `CUSTOM_SHUFFLING_PROOF_SECURITY_PARAMETER` in *phoebus/mixnet/params.py* for increased security.

## Acknowledgements

I'd like to thank:

* Ben Adida, for his immense amount of work implementing [Helios](https://github.com/benadida/helios-server)
* Josh Benaloh, for his [*Simple Verifiable Elections*](https://www.usenix.org/legacy/event/evt06/tech/full_papers/benaloh/benaloh.pdf) paper that forms the basis of this family of voting systems
* Lázaro Clapp, Sergio Rajsbaum and Hugo Rodriguez, for their work on [svelib](https://github.com/HRodriguez/svelib), a sine qua non for this project given my lack of cryptographic expertise
* [/u/jnd-au](https://www.reddit.com/user/jnd-au) and the rest of the [Reddit Model Parliament of  Australia](https://www.reddit.com/r/ModelAustralia/) community for testing and suggesting improvements

## Licence

Copyright © 2016 RunasSudo (Yingtong Li)    
Based on code by GRnet researchers (https://github.com/grnet/zeus), licensed under the GPLv3.    
Based on code by Ben Adida (https://github.com/benadida/helios-server), licensed under the Apache License.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

### Disclaimer

While the creators of the original Helios and Zeus are crypto experts, I am not. I cannot guarantee the security of this implementation whatsoever.

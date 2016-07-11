# helios-server-mixnet standalone scripts

## mix.py
Requires a Python 2 virtual environment.

    ./mix.py ballots.json shuffle.json proof.json

Takes as input a JSON file containing a list of ballots (as shown in each mixnet's homepage when time to shuffle), and outputs a JSON file containing the shuffled ballots, and a JSON file containing the proof of shuffle.

## export.sh
    ./export.sh

Exports the election as configured in the file to the current directory in a format suitable for `verify.py`.

## verify.py
Requires a Python 2 virtual environment.

    ./verify.py --type local --uuid 12345678-90ab-cdef-1234-567890abcdef ~/path/to/election/dump
    ./verify.py --type remote https://helios.example.com/helios/elections/12345678-90ab-cdef-1234-567890abcdef

Gets the data for a Helios mixnet election and verifies the shuffles and decryption.

## count/*_to_blt.py
Requires **Python 3**.

    ./gamma_to_blt.py election.json result.json 2

Takes as input a JSON file containing the [raw data for an election](https://helios.example.com/helios/elections/12345678-90ab-cdef-1234-567890abcdef), the [raw result](https://helios.example.com/helios/elections/12345678-90ab-cdef-1234-567890abcdef/result) and the number of seats to be filled, and outputs an [OpenSTV blt file](https://stackoverflow.com/questions/2233695/how-do-i-generate-blt-files-for-openstv-elections-using-c) able to be piped into the count scripts.

## count/wright_stv.py
Requires **Python 3**.

    ./wright_stv.py election.blt

Takes as input a JSON file containing an [OpenSTV blt file](https://stackoverflow.com/questions/2233695/how-do-i-generate-blt-files-for-openstv-elections-using-c), and calculates the winners under [Wright STV](http://www.aph.gov.au/Parliamentary_Business/Committees/House_of_Representatives_Committees?url=/em/elect07/subs/sub051.1.pdf).

### Performing a countback
These scripts can be used to perform a Hare-Clark-style countback to fill vacancies. Firstly, we must capture the quota of votes used to finally elect the candidate causing the vacancy:

    ./wright_stv.py election.blt --countback CandidateName countback.blt

This command will output a new blt file containing only this quota of votes. We can then run an instant-runoff election with these votes.

    ./irv.py countback.blt

If some candidates have chosen not to contest the countback, you can add an `-ID` line into the blt file in the withdrawn candidates block, where `ID` is the 1-indexed position of the candidate in the candidate list.

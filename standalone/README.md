# helios-server-mixnet standalone scripts

## mix.py
Requires a Python 2 virtual environment.

    ./mix.py ballots.json shuffle.json proof.json

Takes as input a JSON file containing a list of ballots (as shown in each mixnet's homepage when time to shuffle), and outputs a JSON file containing the shuffled ballots, and a JSON file containing the proof of shuffle.

If there are many questions, it is also possible to mix each question separately and combine them at the end to avoid issues half-way through a mix. For example:

    for i in {0..2}; do ./mix.py ballots.json shuffle$i.json proof$i.json $i; done
    ./combine.py shuffle.json proof.json {shuf,proof}{0..2}.json

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

The votes can then be counted using [pyRCV](https://github.com/RunasSudo/pyRCV).

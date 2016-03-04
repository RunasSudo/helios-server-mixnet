# helios-server-mixnet standalone scripts

## mix.py
Requires a Python 2 virtual environment.

    ./mix.py ballots.json shuffle.json proof.json

Takes as input a JSON file containing a list of ballots (as shown in each mixnet's homepage when time to shuffle), and outputs a JSON file containing the shuffled ballots, and a JSON file containing the proof of shuffle.

## verify.py
Requires a Python 2 virtual environment.

    ./verify.py https://helios.example.com/helios/elections/12345678-90ab-cdef-1234-567890abcdef

Downloads the data for a Helios mixnet election and verifies the shuffles and decryption.

## count/*_to_gamma.py
Requires **Python 3**.

    ./csv_to_gamma.py candidates.csv ballots.csv

Takes as input a list of candidates (one per line) and a list of CSV ballots (one ballot per line, candidate names separated by commas), and outputs a result array able to be piped into the count scripts.

    ./blt_to_gamma.py ballots.blt

Takes as input an [OpenSTV blt file](https://stackoverflow.com/questions/2233695/how-do-i-generate-blt-files-for-openstv-elections-using-c), and outputs a result array able to be piped into the count scripts.

## count/wright_stv.py
Requires **Python 3**.

    ./wright_stv.py election.json result.json 2

Takes as input a JSON file containing the [raw data for an election](https://helios.example.com/helios/elections/12345678-90ab-cdef-1234-567890abcdef), the [raw result](https://helios.example.com/helios/elections/12345678-90ab-cdef-1234-567890abcdef/result) and the number of seats to be filled, and calculates the winners under [Wright STV](http://www.aph.gov.au/Parliamentary_Business/Committees/House_of_Representatives_Committees?url=/em/elect07/subs/sub051.1.pdf).
#!/bin/bash
UUID=12345678-90ab-cdef-1234-567890abcdef
BASE=http://127.0.0.1:8000/helios/elections/$UUID

curl -v -o $UUID.json $BASE

mkdir $UUID
curl -v -o $UUID/meta.json $BASE/meta
curl -v -o $UUID/trustees.json $BASE/trustees/
curl -v -o $UUID/result.json $BASE/result
curl -v -o $UUID/voters.json $BASE/voters/
curl -v -o $UUID/ballots.json $BASE/ballots/

curl -v -o $UUID/mixnets.json $BASE/mixnets/
NUM_MIX=$(grep -o '{' $UUID/mixnets.json | wc -l) # you thought parsing XML with regex was bad?
mkdir $UUID/mixnets
for i in $(seq 0 $(($NUM_MIX-1))); do
	mkdir $UUID/mixnets/$i
	curl -v -o $UUID/mixnets/$i/answers.json $BASE/mixnets/$i/answers
	curl -v -o $UUID/mixnets/$i/proof.json $BASE/mixnets/$i/proof
done

dcrtime_checker
==============

There are circumstances where one may want to verify a prior server anchor
against the blockchain directly. This tool takes the original anchor response
and verifies proof of existence using the following process:
 1. Ensure file digest is included in the anchor record
 2. Verify the merkle root and path
 3. Verify that the anchor exists in the blockchain


## Flags

```
  -f		Original filename
  -h		Non default block explorer host. Defaults based on -testnet flag.
  -p		Original JSON anchor record
  -testnet	Use testnet.
  -v		Verbose
```

## Important

One *must* store the original anchor record in order to use this tool.

For example, use the dcrtime command line utility to verify that the record has
been anchored.
```
$ dcrtime -v d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517
d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517 Verify
d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517 OK
  Chain Timestamp: 1531224216
  Merkle Root    : fe9680ca605b6af488b8ded0d5ef28506758745eedca56c220d6b7c89226c85c
  TxID           : 0066578e01764c65fbc48870d8315d9bb7ead3a25e0318a0d8e7fdb52ef4ff87
```

Store proof:
```
$ dcrtime -json d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517 > proof.json
```

This proof looks like this:
```
{"id":"dcrtime cli","digests":[{"digest":"d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517","servertimestamp":1553799600,"result":0,"chaininformation":{"chaintimestamp":1531224216,"transaction":"0066578e01764c65fbc48870d8315d9bb7ead3a25e0318a0d8e7fdb52ef4ff87","merkleroot":"fe9680ca605b6af488b8ded0d5ef28506758745eedca56c220d6b7c89226c85c","merklepath":{"NumLeaves":3,"Hashes":[[127,70,80,89,228,171,127,105,76,251,211,241,162,43,49,165,124,141,27,134,120,100,70,162,253,181,237,147,238,244,53,98],[209,114,25,24,177,172,201,175,93,182,41,71,167,174,82,115,139,124,76,85,226,209,24,156,80,107,235,114,209,7,149,23]],"Flags":"DQ=="}}}],"timestamps":[]}
```

## Examples

Verify proof of existence:
```
$ dcrtime_checker -v -f LICENSE -p proof.json                              
d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517  LICENSE
d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517  Proof  OK
d1721918b1acc9af5db62947a7ae52738b7c4c55e2d1189c506beb72d1079517  Anchor OK
```


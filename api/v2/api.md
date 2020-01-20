# dcrtime API Specification

## V2

This document describes the REST API provided by a `dcrtimed` server. This API 
allows users to create and upload hashes which are periodically submitted to 
the Decred blockchain. It gives the option to send a single string digest, as 
well as multiples in a array of string digests. It also provides the ability 
to confirm the addition of the hash to a timestamped collection along with 
showing and validating their inclusion in the Decred blockchain.

**Methods**

- [`Timestamp`](#timestamp)
- [`Timestamps`](#timestamps)
- [`Verify`](#verify)

**Return Codes**

- [`ResultOK`](#ResultOK)
- [`ResultExistsError`](#ResultExistsError)
- [`ResultDoesntExistsError`](#ResultDoesntExistsError)
- [`ResultDisabled`](#ResultDisabled)

### Methods

#### `Timestamp`

Upload one digest to the time server. The server will then add this digest to
a collection and eventually to a transaction that goes in a Decred block. 
This method returns immediately with the collection the digest has been added 
to.You must use the verify call to find out when it has been anchored to a 
block (which is done in batches at a set time interval that is not related 
to the api calls).

* **URL**

  `/v2/timestamp/`

* **HTTP Method:**

  `POST`

*  *Params*

	**Required**

   `digest={hash}`

    Digest is a digest (SHA256 hash) to send to the server.

	**Optional**

   `id=[string]`

	ID is a user provided identifier that may be used in case the client 
	requires a unique identifier.

* **Results**

	`id`

	id is copied from the original call for the client to use to match calls
	 and responses.

	`servertimestamp`

	servertimestamp is the collection the digests belong to.

	`digest`

	digest is the digest processed by the server.

	`result`

	result is a integer representing the result for the digest. See #Result
	 for details on return codes.

* **Example**

Request:

```json
{
    "id":"dcrtime cli",
    "digest": 
		"d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13"
}
```

Reply:

```json
{
    "id":"dcrtime cli",
	"servertimestamp":1497376800,
	"digest": 
		"d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13",
	"result": 1
}
```

#### `Timestamps`

Upload multiple digests to the time server. Behaves the same as /v2/timestamp, 
except for the ability to send multiple digests in a single request.

* **URL**

  `/v2/timestamps/`

* **HTTP Method:**

  `POST`

*  *Params*

	**Required**

   `digests=[{hash},{...}]`

    Digests is an array of digests (SHA256 hashes) to send to the server.

	**Optional**

   `id=[string]`

	ID is a user provided identifier that may be used in case the client 
	requires a unique identifier.

* **Results**

	`id`

	id is copied from the original call for the client to use to match calls
	 and responses.

	`servertimestamp`

	servertimestamp is the collection the digests belong to.

	`digests`

	digests is the list of digests processed by the server.

	`results`

	results is a list of integers representing the result for each digest.  
	See #Results for details on return codes.

* **Example**

Request:

```json
{
    "id":"dcrtime cli",
    "digests":[
        "d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13"
    ]
}
```

Reply:

```json
{
    "id":"dcrtime cli",
	"servertimestamp":1497376800,
	"digests":[
	    "d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13"
	],
	"results":[
	    1
	]
}
```

#### `Verify`

Verifies the status of a batch of digests or timestamps on the server. If 
verifying digests, it'll return the chain information relative to that digest, 
including its merkle path. If verifying timestamps, it'll return the 
collection information relative to that timestamp, including all the digests 
grouped on that collection. If it has not been anchored on the blockchain yet, 
it returns zero. Digests and timestamps can be verified on the same request.

* **URL**

  `/v2/verify/`

* **HTTP Method:**

  `POST`

*  *Params*

	**Required**

	`digests=[{hash},{...}]`

	Digests is an array of digests (SHA256 hashes) to send to the server.

	or

	`timestamps=[{timestamp}, {...}]`


	Timestamps is an array of int64 timestamps to be confirmed by the server.

	**Optional**

   `id=[string]`

	ID is a user provided identifier that may be used in case the client 
	requires a unique identifier.

* **Results**

	`id`

	id is copied from the original call for the client to use to match calls
	and responses.

	`digests`

	The batch of digests requested by the client. Each digest will return the
	following fields:

	`digest`

	The digest processed by the server.

	`servertimestamp`

	The collection the digest belongs to (if anchored).

	`result`

	Return code, see #Results.

	`chaininformation`

	A JSON object with the information about the onchain timestamp.

	`chaintimestamp`

	Timestamp from the server.

	`transaction`

	Transaction hash that includes the digest.

	`merkleroot`

	MerkleRoot of the block containing the transaction (if mined).

	`merklepath`

	Merklepath contains additional information for the mined transaction 
	(if available).

	`timestamps`

	The batch of timestamps requested by the client. Each timestamp will return
	 the following fields:

	`servertimestamp`

	The timestamp itself.

	`result`

	Return code, see #Results.

	`collectioninformation`	

	A JSON object with the information about that timestamp collection.

	`chaintimestamp`

	Timestamp from the server.

	`transaction` 

	Transaction hash that includes the digest.

	`merkleroot`

	MerkleRoot of the block containing the transaction (if mined).

	`digests`	

	Digests contains all digests grouped and anchored on that timestamp 
	collection.


* **Example**

Request:

```json
{
    "id":"dcrtime cli",
	"digests":[
        "d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13"
    ],
	"timestamps": [
		1497376800
	]
}
```

Reply:

```json
{
    "id":"dcrtime cli",
	"digests":[{
	    "digest":
			"d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13",
	    "servertimestamp":1497376800,
	    "result":0,
	    "chaininformation":{
	        "chaintimestamp":0,
	        "transaction":
			"0000000000000000000000000000000000000000000000000000000000000000",
	        "merkleroot":
			"0000000000000000000000000000000000000000000000000000000000000000",
	        "merklepath":{
	            "NumLeaves":0,
	            "Hashes":null,
	            "Flags":null
	        }
	    }
	}],
	"timestamps":[{
		"servertimestamp":1497376800,
		"result":0,
		"collectioninformation":{
			"chaintimestamp":0,
			"transaction":
			"0000000000000000000000000000000000000000000000000000000000000000",
			"merkleroot":
			"0000000000000000000000000000000000000000000000000000000000000000",
			"digests":[
			"d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13"
			]
		}
	}]
}
```

### Results

* `ResultOK`

	`0`

	The Operation completed successfully.

* `ResultExistsError`

	`1`

The digest was rejected because it exists.  This is only relevant for the
`Timestamp` call.

* `ResultDoesntExistError`

	`2`

The timestamp or digest could not be found by the server.  This is only 
relevant for the `Verify` call.

* `ResultDisabled`

`3`

Querying is disabled.

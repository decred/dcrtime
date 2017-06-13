# dcrtime API Specificiation

## V1

This document describes the REST API provided by a `dcrtimed` server.  This API allows users to create upload hashes which are periodically submitted to the decred blockchain and timestamped as well as to confirm such timestamps.

**Methods**

- [`Timestamp`](#timestamp)
- [`Verify`](#verify)

**Return Codes**

- [`ResultOK`](#ResultOK)
- [`ResultExistsError`](#ResultExistsError)
- [`ResultDoesntExistsError`](#ResultDoesntExistsError)
- [`ResultDisabled`](#ResultDisabled)

### Methods

#### `Timestamp`

Query the server to store one or more digests and return a collection the will contain the supplied digest.

* **URL**

  `/v1/timestamp/`

* **HTTP Method:**

  `POST`

*  *Params*

	**Required**

   `digests=[{hash},{...}]`

    Digest is an array of digests (SHA256 hashes) to send to the server.

	**Optional**

   `id=[string]`

	ID is a user provided identifier that may be used in case the client requires a unique identifier.

* **Results**

	`id`

	id is copied from the original call for the client to use to match calls and responses.

	`servertimestamp`

	servertimestamp is the collection the digests belong to.

	`digests`

	digests is the list of digests processed by the server.

	`results`

	results is a list of integers representing the result for each digest.  See #Results for details on return codes.

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

* **URL**

  `/v1/verify/`

* **HTTP Method:**

  `POST`

*  *Params*

	**Required**

	`digests=[{hash},{...}]`

	A list of hashes to be confirmed by the server.

	**Optional**

   `id=[string]`

	ID is a user provided identifier that may be used in case the client requires a unique identifier.

* **Results**

	`id`

	id is copied from the original call for the client to use to match calls and responses.

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

	Merklepath of the block containint the transaction (if mined).

* **Example**

Request:

```json
{
    "id":"dcrtime cli",
	"digests":[
        "d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13"
    ],
	"timestamps":null
}
```

Reply:

```json
{
    "id":"dcrtime cli",
	"digests":[{
	    "digest":"d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13",
	    "servertimestamp":1497376800,
	    "result":0,
	    "chaininformation":{
	        "chaintimestamp":0,
	        "transaction":"0000000000000000000000000000000000000000000000000000000000000000",
	        "merkleroot":"0000000000000000000000000000000000000000000000000000000000000000",
	        "merklepath":{
	            "NumLeaves":0,
	            "Hashes":null,
	            "Flags":null
	        }
	    }
	}],
	"timestamps":[]
}
```

### Results

* `ResultOK`

	`0`

	The Operation completed succefully.

* `ResultExistsError`

	`1`

The digest was rejected because it exists.  This is only relevant for the `Timestampe` call.

* `ResultDoesntExistError`

	`2`

The timestamp or digest could not be found by the server.  This is only relevant for the `Verify` call.

* `ResultDisabled`

`3`

Querying is disabled.

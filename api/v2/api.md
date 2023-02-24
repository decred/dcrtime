# dcrtime API Specification

## V2

This document describes the REST API provided by a `dcrtimed` server. This API
allows users to create and upload hashes which are periodically submitted to
the Decred blockchain. It gives the option to send a single string digest, as
well as multiples in a array of string digests. It also provides the ability
to confirm the addition of the hash to a timestamped collection along with
showing and validating their inclusion in the Decred blockchain.

**Methods**

- [`Timestamp Batch`](#timestampBatch)
- [`Verify Batch`](#verifyBatch)

- [`Timestamp`](#timestamp)
- [`Verify`](#verify)
- [`Last Digests`](#last-digests)

**Return Codes**

- [`ResultInvalid`](#ResultInvalid)
- [`ResultOK`](#ResultOK)
- [`ResultExistsError`](#ResultExistsError)
- [`ResultDoesntExistsError`](#ResultDoesntExistsError)
- [`ResultDisabled`](#ResultDisabled)

### Methods


#### `Timestamp Batch`

Upload multiple digests to the time server. The server adds this
digest to a collection and eventually to a transaction that goes in a Decred
block. This method returns immediately with the collection the digest has been
added to. You must use the verify call to find out when it has been anchored to
a block (which is done in batches at a set time interval that is not related to
the api calls).

* **URL**

  `/v2/timestamp/batch`

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

#### `Verify Batch`

Verifies the status of a batch of digests or timestamps on the server. If
verifying digests, it'll return the chain information relative to that digest,
including its merkle path. If verifying timestamps, it'll return the
collection information relative to that timestamp, including all the digests
grouped on that collection. If it has not been anchored on the blockchain yet,
it returns zero. Digests and timestamps can be verified on the same request.

* **URL**

  `/v2/verify/batch`

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

#### `Timestamp`

Upload one digest to the time server from a pure HTML form data on the client
side. This route exists to serve no-JS clients. Anchors the digest to the
server the same way as batched ones.

* **URL**

  `/v2/timestamp`

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

Request form data:

| Key  |  Value  |
| ------------------- | ------------------- |
|  id |  dcrtime cli |
|  digest |  d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13 |

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

### Results

* `ResultInvalid`

	`0`

The requested operation was invalid.

* `ResultOK`

	`1`

The operation completed successfully.

* `ResultExistsError`

	`2`

The digest was rejected because it exists. This is only relevant for the
`Timestamp` call.

* `ResultDoesntExistError`

	`3`

The timestamp or digest could not be found by the server. This is only
relevant for the `Verify` call.

* `ResultDisabled`

	`4`

Querying is disabled.

#### `Verify`

Verifies the status of a digest or timestamp on the server. Verifies through
the same process as batched ones.

* **URL**

  `/v2/verify`

* **HTTP Method:**

  `POST`

*  *Params*

	**Required**

	`digest={hash}`

	Digest is a digest (SHA256 hash) to be confirmed by the server.

	or

	`timestamp={timestamp}`


	Timestamp is a int64 timestamp to be confirmed by the server.

	**Optional**

   `id=[string]`

	ID is a user provided identifier that may be used in case the client
	requires a unique identifier.

* **Results**

	`id`

	id is copied from the original call for the client to use to match calls
	and responses.

	`digest`

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

	`timestamp`

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

Request form data:

| Key  |  Value  |
| ------------------- | ------------------- |
|  id |  dcrtime cli |
|  digest |  d412ba345bc44fb6fbbaf2db9419b648752ecfcda6fd1aec213b45a5584d1b13 |
|  timestamp |  1497376800 |

Reply:

```json
{
    "id":"dcrtime cli",
	"digest": {
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
	},
	"timestamp": {
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
	}
}
```

#### Last Digests

This method is used to ask the server the info about the last digests added. It receives a `number` as a parameter and returns an array with info about the last `number` digests in the server. **Note:** the max `number` of digests that can be queried is defined by a `maxdigests` config variable and its default value is 20.

**URL:**

  `/v2/last-digests`

**HTTP Method:**

  `POST`

**Params:**

| Param  |  Type  |
| ------ | ------ |
| number |   int  |

**Results:**

An array of size `number` where each value is of [Verify](#verify) type.

**Example:**

Request:

```json
{"number":3}
```

Reply:

```json
{
   "digests":[
      {
         "digest":"2c9a1c95814f31bb8459a7f7fc3536e73354699bace060e0876966878e1d1548",
         "servertimestamp":1668078900,
         "result":1,
         "chaininformation":{
            "chaintimestamp":1668079484,
            "transaction":"d93e0f68721569a11eb9743fdfb264207a1a9876d8615d5a9714776c1825e256",
            "merkleroot":"08fa2aab70b371ee5bcce8ed6448e6a43a5f9e2aa614a53152cb819db3aac009",
            "merklepath":{
               "NumLeaves":3,
               "Hashes":[
                  [
                     132,
                     213,
                     10,
                     173,
                     220,
                     181,
                     230,
                     211,
                     48,
                     110,
                     146,
                     125,
                     96,
                     180,
                     178,
                     218,
                     92,
                     198,
                     73,
                     183,
                     98,
                     50,
                     24,
                     136,
                     183,
                     75,
                     156,
                     128,
                     170,
                     94,
                     91,
                     245
                  ]
               ],
               "Flags":"AA=="
            }
         }
      },
      {
         "digest":"869436ec0a37536e19161a2cd23cab04fcaf71861969af83fc13b52e79350e00",
         "servertimestamp":1668078900,
         "result":1,
         "chaininformation":{
            "chaintimestamp":1668079484,
            "transaction":"d93e0f68721569a11eb9743fdfb264207a1a9876d8615d5a9714776c1825e256",
            "merkleroot":"08fa2aab70b371ee5bcce8ed6448e6a43a5f9e2aa614a53152cb819db3aac009",
            "merklepath":{
               "NumLeaves":3,
               "Hashes":[
                  [
                     132,
                     213,
                     10,
                     173,
                     220,
                     181,
                     230,
                     211,
                     48,
                     110,
                     146,
                     125,
                     96,
                     180,
                     178,
                     218,
                     92,
                     198,
                     73,
                     183,
                     98,
                     50,
                     24,
                     136,
                     183,
                     75,
                     156,
                     128,
                     170,
                     94,
                     91,
                     245
                  ]
               ],
               "Flags":"AA=="
            }
         }
      },
      {
         "digest":"b074c20bd8a9e4a3bdc760fd9cf33d2417fe4489c2a1c9497ddf48bf9ed7c118",
         "servertimestamp":1668078900,
         "result":1,
         "chaininformation":{
            "chaintimestamp":1668079484,
            "transaction":"d93e0f68721569a11eb9743fdfb264207a1a9876d8615d5a9714776c1825e256",
            "merkleroot":"08fa2aab70b371ee5bcce8ed6448e6a43a5f9e2aa614a53152cb819db3aac009",
            "merklepath":{
               "NumLeaves":3,
               "Hashes":[
                  [
                     176,
                     116,
                     194,
                     11,
                     216,
                     169,
                     228,
                     163,
                     189,
                     199,
                     96,
                     253,
                     156,
                     243,
                     61,
                     36,
                     23,
                     254,
                     68,
                     137,
                     194,
                     161,
                     201,
                     73,
                     125,
                     223,
                     72,
                     191,
                     158,
                     215,
                     193,
                     24
                  ],
                  [
                     176,
                     116,
                     194,
                     11,
                     216,
                     169,
                     228,
                     163,
                     189,
                     199,
                     96,
                     253,
                     156,
                     243,
                     61,
                     36,
                     23,
                     254,
                     68,
                     137,
                     194,
                     161,
                     201,
                     73,
                     125,
                     223,
                     72,
                     191,
                     158,
                     215,
                     193,
                     24
                  ],
                  [
                     176,
                     116,
                     194,
                     11,
                     216,
                     169,
                     228,
                     163,
                     189,
                     199,
                     96,
                     253,
                     156,
                     243,
                     61,
                     36,
                     23,
                     254,
                     68,
                     137,
                     194,
                     161,
                     201,
                     73,
                     125,
                     223,
                     72,
                     191,
                     158,
                     215,
                     193,
                     24
                  ]
               ],
               "Flags":"Pw=="
            }
         }
      }
   ]
}
```
# Dcrtime Relational Database

This document describes the SQL relational tables used in dcrtime.

We have two tables storing all timestamped digests information, `records` 
and `anchors` where the first is the first is key/value like used to store all 
timestamped digests and the second for storing anchors information, where each 
succesful anchor will result in a new entry. Each `record` which was included 
in an `anchor` will be connected to the corresponding entry in the anchors 
table using the col `anchor_merkle` which defined as forgein key & indexed in 
records table, below you find the detailed description of the two table:


### Tables

**Records:**
| Col Name             | Type              | Not Null | P. Key | F. Key | Indexed | Description                                                    |
|----------------------|-------------------|----------|--------|--------|---------|----------------------------------------------------------------|
| key                  | serial            | x        | x      |        |         | Auto incremented  identifier                                   |
| collection_timestamp | text              | x        |        |        | x       | Unix timestamp of collection                                   |
| digest               | bytea             | x        |        |        |         | Timestamped digest                                             |
| anchor_merkle        | char. varying(64) |          |        | x      | x       | Merkle root of corresponding anchor,   nil if not anchored yet |



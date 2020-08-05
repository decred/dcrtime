# Dcrtime Relational Database

This document describes the SQL relational tables used in dcrtime.

We have two tables storing all timestamped digests information, `records` 
and `anchors` where the first is key/value like table used to store all 
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
| anchor_merkle        | char. varying(64) |          |        | x      | x       | Merkle root of corresponding anchor - linking to anchors table, nil if not anchored yet |

**Anchors:**
| Col Name         | Type              | Not Null | P. Key | F. Key | Indexed | Description                     |
|------------------|-------------------|----------|--------|--------|---------|---------------------------------|
| merkle           | char. varying(64) | x        | x      |        |         | Anchor merkle root              |
| hashes           | text[]            | x        |        |        |         | Anchored hashes                 |
| tx_hash          | text              |          |        |        |         | Anchor tx hash                  |
| chain_timestamp  | bigint            |          |        |        | x       | Anchor timestamp on blockchain  |
| flush_timestamp  | bigint            |          |        |        | x       | When anchor actually  flushed   |


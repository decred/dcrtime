# Dcrtime Relational Database

This document describes the SQL relational tables used in dcrtime.

We have two tables storing all timestamped digests information, `records` 
and `anchors` where the first is used to store all timestamped digest and 
the second for storing anchors information, where each succesful anchor 
will result in new entry. Each `record` which was included in an `anchor` 
will be connected to the corresponding entry in the anchors table using 
the col `anchor_merkle` which defined as forgein key & indexed in 
records table, below you find the detailed description of the two table:



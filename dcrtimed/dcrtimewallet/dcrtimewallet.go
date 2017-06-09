// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrtimewallet

import (
	"context"
	"crypto/sha256"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
)

type DcrtimeWallet struct {
	conn       *grpc.ClientConn
	wallet     pb.WalletServiceClient
	ctx        context.Context
	passphrase []byte
}

type Result struct {
	Block         chainhash.Hash
	Timestamp     int64
	Confirmations int32
}

// Lookup looks up the provided TX hash and returns a Result structure.
func (d *DcrtimeWallet) Lookup(tx chainhash.Hash) (*Result, error) {
	ctx, cancel := context.WithCancel(d.ctx)
	defer cancel()

	// Ask how many confirmations we got
	n, err := d.wallet.ConfirmationNotifications(ctx)
	if err != nil {
		return nil, err
	}
	err = n.Send(&pb.ConfirmationNotificationsRequest{
		TxHashes:  [][]byte{tx[:]},
		StopAfter: 0, // We only want one reply
	})
	if err != nil {
		return nil, err
	}
	r, err := n.Recv()
	if err != nil {
		return nil, err
	}
	if len(r.Confirmations) != 1 {
		return nil, fmt.Errorf("invalid reply length: %v",
			len(r.Confirmations))
	}

	// Sanity test confirmations reply
	h, err := chainhash.NewHash(r.Confirmations[0].TxHash)
	if err != nil {
		return nil, err
	}
	if !h.IsEqual(&tx) {
		return nil, fmt.Errorf("invalid tx hash: %v", tx.String())
	}

	// Abort early if we don't have enough confirmations.
	if r.Confirmations[0].Confirmations <= 0 {
		return &Result{
			Confirmations: r.Confirmations[0].Confirmations,
		}, nil
	}

	// Get timestamp
	rbi, err := d.wallet.BlockInfo(ctx, &pb.BlockInfoRequest{
		BlockHash: r.Confirmations[0].BlockHash,
	})
	if err != nil {
		return nil, err
	}

	block, err := chainhash.NewHash(rbi.BlockHash)
	if err != nil {
		return nil, err
	}

	return &Result{
		Block:         *block,
		Timestamp:     rbi.Timestamp,
		Confirmations: rbi.Confirmations,
	}, nil
}

// Construct creates aand submits an anchored tx with the provided merkle root.
func (d *DcrtimeWallet) Construct(merkleRoot [sha256.Size]byte) (*chainhash.Hash, error) {

	// Generate script that contains OP_RETURN followed by the merkle root.
	script, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).
		AddData(merkleRoot[:]).Script()
	if err != nil {
		return nil, err
	}

	// Create transaction request.
	constructRequest := &pb.ConstructTransactionRequest{
		SourceAccount:            0,
		RequiredConfirmations:    2,
		FeePerKb:                 0, // let wallet decide the fee
		OutputSelectionAlgorithm: pb.ConstructTransactionRequest_UNSPECIFIED,
		NonChangeOutputs: []*pb.ConstructTransactionRequest_Output{
			{
				Destination: &pb.ConstructTransactionRequest_OutputDestination{
					Script:        script,
					ScriptVersion: 0,
				},
				Amount: 0,
			},
		},
	}
	constructResponse, err := d.wallet.ConstructTransaction(d.ctx,
		constructRequest)
	if err != nil {
		return nil, err
	}

	// Sign request.
	signRequest := &pb.SignTransactionRequest{
		Passphrase:            d.passphrase,
		SerializedTransaction: constructResponse.UnsignedTransaction,
	}
	signResponse, err := d.wallet.SignTransaction(d.ctx, signRequest)
	if err != nil {
		return nil, err
	}

	// Publish transaction.
	publishRequest := &pb.PublishTransactionRequest{
		SignedTransaction: signResponse.Transaction,
	}
	publishResponse, err := d.wallet.PublishTransaction(d.ctx,
		publishRequest)
	if err != nil {
		return nil, err
	}

	// Return transaction hash.
	txHash, err := chainhash.NewHash(publishResponse.TransactionHash)
	if err != nil {
		return nil, err
	}
	return txHash, nil
}

// Close shuts down the gRPC connection to the wallet.
func (d *DcrtimeWallet) Close() {
	d.conn.Close()
}

// New returns a DcrtimeWallet context.
func New(cert, host string, passphrase []byte) (*DcrtimeWallet, error) {
	d := &DcrtimeWallet{
		ctx:        context.Background(),
		passphrase: passphrase,
	}

	creds, err := credentials.NewClientTLSFromFile(cert, "")
	if err != nil {
		return nil, err
	}

	log.Infof("Wallet: %v", host)
	d.conn, err = grpc.Dial(host, grpc.WithBlock(),
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	d.wallet = pb.NewWalletServiceClient(d.conn)

	return d, nil
}

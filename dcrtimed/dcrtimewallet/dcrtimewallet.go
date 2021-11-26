// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrtimewallet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	pb "decred.org/dcrwallet/rpc/walletrpc"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type DcrtimeWallet struct {
	account    uint32
	minconf    int32
	conn       *grpc.ClientConn
	wallet     pb.WalletServiceClient
	ctx        context.Context
	passphrase []byte
}

type TxLookupResult struct {
	BlockHash     chainhash.Hash
	Timestamp     int64
	Confirmations int32
	BlockHeight   int32
}

// BalanceResult contains information about the backing dcrwallet
// account balance connected to by dcrtimed.
type BalanceResult struct {
	Total       int64
	Spendable   int64
	Unconfirmed int64
}

// Lookup looks up the provided TX hash and returns a Result structure.
func (d *DcrtimeWallet) Lookup(tx chainhash.Hash) (*TxLookupResult, error) {
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
		return &TxLookupResult{
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

	return &TxLookupResult{
		BlockHash:     *block,
		Timestamp:     rbi.Timestamp,
		Confirmations: rbi.Confirmations,
		BlockHeight:   rbi.BlockHeight,
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

	// Request a change address while ignoring the gap policy.
	nextAddressRequest := &pb.NextAddressRequest{
		Account:   d.account,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_IGNORE,
	}
	nextAddressResponse, err := d.wallet.NextAddress(d.ctx, nextAddressRequest)
	if err != nil {
		return nil, err
	}

	// Create transaction request.
	constructRequest := &pb.ConstructTransactionRequest{
		SourceAccount:            d.account,
		RequiredConfirmations:    d.minconf,
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
		ChangeDestination: &pb.ConstructTransactionRequest_OutputDestination{
			Address: nextAddressResponse.Address,
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

// GetWalletBalance returns balance information from the
// wallet account.
func (d *DcrtimeWallet) GetWalletBalance() (*BalanceResult, error) {
	balanceRequest := &pb.BalanceRequest{
		AccountNumber:         d.account,
		RequiredConfirmations: d.minconf,
	}

	balanceResponse, err := d.wallet.Balance(d.ctx, balanceRequest)
	if err != nil {
		return nil, err
	}

	accountBalance := &BalanceResult{
		Total:       balanceResponse.Total,
		Spendable:   balanceResponse.Spendable,
		Unconfirmed: balanceResponse.Unconfirmed,
	}

	return accountBalance, nil
}

// Close shuts down the gRPC connection to the wallet.
func (d *DcrtimeWallet) Close() {
	d.conn.Close()
}

// New returns a DcrtimeWallet context.
func New(cert, host, clientCert, clientKey string, passphrase []byte) (*DcrtimeWallet, error) {
	d := &DcrtimeWallet{
		account:    0,
		minconf:    2,
		ctx:        context.Background(),
		passphrase: passphrase,
	}

	serverCAs := x509.NewCertPool()
	serverCert, err := ioutil.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	if !serverCAs.AppendCertsFromPEM(serverCert) {
		return nil, fmt.Errorf("no certificates found in %s",
			cert)
	}
	keypair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("read client keypair: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keypair},
		RootCAs:      serverCAs,
	})

	log.Infof("Wallet: %v", host)
	d.conn, err = grpc.Dial(host, grpc.WithBlock(),
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	d.wallet = pb.NewWalletServiceClient(d.conn)

	return d, nil
}

package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/crypto"
	"github.com/livepeer/go-livepeer/pm"
)

func main() {
	msg := "eyJpZCI6ImE0MDdiNjJjIiwidG9rZW4iOnsidG9rZW4iOiJ2aERudCtiV2pCcnh6ejVnNTBxOW5Vdk5tNGxZQ3g0eFdzKzB0alE1NjBrPSIsInNlc3Npb25faWQiOiJhNDA3YjYyYyIsImV4cGlyYXRpb24iOjE3MDU0MTU0MTJ9LCJkYXRhSGFzaCI6IjB4ZDcyNDgyNmFhOGRlMDA5ZDI5N2U2Y2IwNDhmOGI0ODIyZTZiZGJhOGZmZWI1MzYxOGVmM2QyZTg5NGRmZDZiMSIsImNhcGFiaWxpdHkiOiJzdGFibGUtdmlkZW8tZGlmZnVzaW9uIiwicHJvbXB0Ijoic3RhYmxlLXZpZGVvLWRpZmZ1c2lvbiIsInBhcmFtZXRlcnMiOiJ7XCJzZWVkXCI6XCItMVwiLFwiZnBzXCI6XCIyNVwiLFwibW90aW9uX2J1Y2tldF9pZFwiOlwiMTgwXCIsXCJub2lzZV9hdWdfc3RyZW5ndGhcIjpcIi4xXCJ9In0="
	sig := "0xfd9fa743b64090504bc9ee8d3a589d3fdce8f797d4ca5a18e001054bdd576e3517bf7459b048340018a818fd4a7b51ad1f67eadcc4dd437073f6f8b053c183f71b"
	msgb := []byte(msg)
	sigb, _ := hexutil.Decode(sig)
	fmt.Println(fmt.Sprintf("%v", crypto.VerifySig(ethcommon.HexToAddress("0xEe2b537e47d0f14bF1E3A9aA0AFB7B34b0F30012"),
		[]byte("0xb4c6a87141511a399385a104103ea1b9be5dd710613e3a04bc18292b18a226ea"),
		sigb)))

	hash := ethcrypto.Keccak256Hash(msgb)
	fmt.Println(fmt.Sprintf("hash of msg: %v", hash.Hex()))
	fmt.Println(fmt.Sprintf("compared to: %v", "0xb56867d6cdb1557e0a5628930f00a0e4130074de44241fb498dc5670c1ccf729"))

	personalHash := accounts.TextHash([]byte(hash.Hex()))
	//personalHash := ethcrypto.Keccak256([]byte(personalMsg))

	if sigb[ethcrypto.RecoveryIDOffset] == 27 || sigb[ethcrypto.RecoveryIDOffset] == 28 {
		sigb[ethcrypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	}
	recovered, err := ethcrypto.Ecrecover(personalHash, sigb)
	if err != nil {
		glog.Errorf("recover failed: %v", err.Error())
		return
	}
	addr := PublicKeyBytesToAddress(recovered)
	fmt.Println(fmt.Sprintf("computed address: %v", addr.Hex()))

	fmt.Println(fmt.Sprintf("%v", crypto.VerifyPersonalSig("0xEe2b537e47d0f14bF1E3A9aA0AFB7B34b0F30012", sig, "0xb56867d6cdb1557e0a5628930f00a0e4130074de44241fb498dc5670c1ccf729")))

	fv, _ := new(big.Int).SetString("2000000000000000", 10)
	wp, _ := new(big.Int).SetString("2836906186314246787877489132712853742405114624308193818966710857000000000", 10)
	ticket := &pm.Ticket{
		Recipient:              ethcommon.HexToAddress("0x3b28a7d785356dc67c7970666747e042305bfb79"),
		Sender:                 ethcommon.HexToAddress("0xee2b537e47d0f14bf1e3a9aa0afb7b34b0f30012"),
		FaceValue:              fv,
		WinProb:                wp,
		SenderNonce:            1,
		RecipientRandHash:      ethcommon.HexToHash("0x423704c01c7382d6b1468abf7e1c24f74f56406e899442694be735844c47c8d8"),
		CreationRound:          3239,
		CreationRoundBlockHash: ethcommon.HexToHash("0xa10b883be81c23a9ebaace3a6b96ec3974d6b7d371802875f5ee9a1922f23394"),
	}

	thash := ticket.Hash()
	fmt.Println(thash.String())
	fmt.Println(ticket.Hash().Hex())

}

func PublicKeyBytesToAddress(publicKey []byte) ethcommon.Address {
	var buf []byte

	hash := ethcrypto.NewKeccakState()
	hash.Write(publicKey[1:]) // remove EC prefix 04
	buf = hash.Sum(nil)
	address := buf[12:]

	return ethcommon.BytesToAddress(address)
}

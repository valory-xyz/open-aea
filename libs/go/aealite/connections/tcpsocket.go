/* -*- coding: utf-8 -*-
* ------------------------------------------------------------------------------
*
*   Copyright 2018-2019 Fetch.AI Limited
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*   you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
*
* ------------------------------------------------------------------------------
 */

package connections

import (
	wallet "aealite/wallet"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"strconv"
)

type TCPSocketChannel struct {
	address       string
	port          uint16
	conn          *tls.Conn
	peerPublicKey string
}

func (sock *TCPSocketChannel) Connect() error {
	var err error
	// ACN handshake: TLS is used for confidentiality, but peer identity is
	// NOT established via the X.509 chain. The peer presents a self-signed
	// certificate whose CA chain has no meaning for us. Instead, immediately
	// after the TLS handshake we read a signature from the wire and verify
	// that the peer signed its own TLS public key bytes using the
	// pre-shared `peerPublicKey` (see the Verify() call below). This
	// application-level signature check is what authenticates the peer.
	//
	// This mirrors the Python implementation in
	// packages/valory/connections/p2p_libp2p_client/connection.py and is
	// the correct pattern for the ACN protocol. Do NOT "fix" this by
	// setting InsecureSkipVerify to false without also wiring up a real
	// CA — that would break the protocol.
	//
	// #nosec G402 -- intentional: see comment above.
	conf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402 intentional, see comment above
		MinVersion:         tls.VersionTLS12,
	}

	sock.conn, err = tls.Dial("tcp", sock.address+":"+strconv.FormatInt(int64(sock.port), 10), conf)

	if err != nil {
		return err
	}

	state := sock.conn.ConnectionState()
	var cert *x509.Certificate

	for _, v := range state.PeerCertificates {
		cert = v
	}

	pub := cert.PublicKey.(*ecdsa.PublicKey)
	publicKeyBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)

	signature, err := sock.Read()
	logger.Debug().Msgf("got signature %d bytes", len(signature))
	if err != nil {
		return err
	}

	pubkey, err := wallet.PubKeyFromFetchAIPublicKey(sock.peerPublicKey)
	if err != nil {
		return err
	}
	ok, err := pubkey.Verify(publicKeyBytes, signature)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("tls signature check failed")

	}
	return nil
}

func (sock *TCPSocketChannel) Read() ([]byte, error) {
	buf := make([]byte, 4)
	_, err := sock.conn.Read(buf)
	if err != nil {
		return buf, err
	}
	size := binary.BigEndian.Uint32(buf)

	buf = make([]byte, size)
	_, err = sock.conn.Read(buf)
	return buf, err
}

func (sock *TCPSocketChannel) Write(data []byte) error {
	size := uint32(len(data))
	buf := make([]byte, 4, 4+size)
	binary.BigEndian.PutUint32(buf, size)
	buf = append(buf, data...)
	_, err := sock.conn.Write(buf)
	logger.Debug().Msgf("wrote data to pipe: %d bytes", size)
	return err
}

func (sock *TCPSocketChannel) Disconnect() error {
	return sock.conn.Close()
}

func NewSocket(address string, port uint16, peerPublicKey string) Socket {
	return &TCPSocketChannel{address: address, port: port, peerPublicKey: peerPublicKey}
}

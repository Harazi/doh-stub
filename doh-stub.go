package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"time"
)

const (
	certFile       = "/home/sam/dev/selfsignedcert/certificate.pem"
	keyFile        = "/home/sam/dev/selfsignedcert/key.pem"
	listenPort     = 5443
	nameserverPort = 53
)

var (
	listenAddr     = []byte{127, 0, 0, 1}
	nameserverAddr = []byte{127, 0, 0, 53}
)

func main() {
	http.HandleFunc("/dns-query", func(w http.ResponseWriter, req *http.Request) {

		w.Header().Set("Accept", "application/dns-message")

		if req.Method != http.MethodPost {
			w.WriteHeader(405) // Method Not Allowed
			return
		}
		if req.Header.Get("content-type") != "application/dns-message" {
			w.WriteHeader(415) // Unsupported Media Type
			return
		}
		if req.ContentLength < 18 { // Minimum size for DNS query
			w.WriteHeader(400)
			return
		}

		buf := make([]byte, req.ContentLength)

		n, err := io.ReadFull(req.Body, buf)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if int64(n) != req.ContentLength {
			fmt.Fprintln(os.Stderr, "Request body length doesn't match content-length header")
			w.WriteHeader(400)
			return
		}

		socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: listenAddr})
		if err != nil {
			log.Fatal(err)
		}
		defer socket.Close()

		socket.SetDeadline(time.Now().Add(time.Second * time.Duration(5)))

		wrote, err := socket.WriteToUDP(buf, &net.UDPAddr{IP: nameserverAddr, Port: nameserverPort})
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				w.WriteHeader(500)
				return
			}
			log.Fatal(err)
		}
		if wrote != len(buf) {
			fmt.Fprintln(os.Stderr, "Read and Wrote are not equal!")
		}

		resBuf := make([]byte, 1500)
		read, remote, err := socket.ReadFromUDP(resBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				w.WriteHeader(500)
				return
			}
			log.Fatal(err)
		}
		if !slices.Equal(remote.IP, nameserverAddr) || remote.Port != nameserverPort {
			fmt.Fprintln(os.Stderr, "Got response but not from the resolver!!!")
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", fmt.Sprint(read))
		w.WriteHeader(200)
		_, err = w.Write(resBuf[:read])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	})

	err := http.ListenAndServeTLS(
		fmt.Sprintf("%d.%d.%d.%d:%d", listenAddr[0], listenAddr[1], listenAddr[2], listenAddr[3], listenPort),
		certFile,
		keyFile,
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
}

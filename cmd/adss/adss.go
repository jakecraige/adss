package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/jakecraige/adss"
)

func main() {
	cmd := os.Args[1]
	var err error
	switch cmd {
	case "split":
		err = split()

	case "recover":
		err = doRecover()

	default:
		err = fmt.Errorf("Unknown command: %s\n", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func split() error {
	splitCmd := flag.NewFlagSet("split", flag.ExitOnError)
	secPtr := splitCmd.String("secret", "", "Secret to split into shares")
	secPathPtr := splitCmd.String("secret-path", "", "File to split into shares")
	adPtr := splitCmd.String("associated-data", "", "Public data to bind with the shares")
	tPtr := splitCmd.Uint("threshold", 0, "Threshold to reconstruct secret")
	nPtr := splitCmd.Uint("count", 0, "Number of shares to create")
	outDirPtr := splitCmd.String("out-dir", ".", "Directory to write the shares to")
	splitCmd.Parse(os.Args[2:])

	if *tPtr == 0 {
		return fmt.Errorf("-threshold is required")
	}
	if *nPtr == 0 {
		return fmt.Errorf("-count is required")
	}

	secret := []byte(*secPtr)
	var err error
	if *secPtr == "" {
		if *secPathPtr == "" {
			return fmt.Errorf("-secret or -secret-path must be provided")
		}

		secret, err = ioutil.ReadFile(*secPathPtr)
		if err != nil {
			return fmt.Errorf("reading %s: %w", *secPathPtr, err)
		}
	}

	as := adss.NewAccessStructure(uint8(*tPtr), uint8(*nPtr))
	shares, err := adss.Share(as, secret, []byte(*adPtr))
	if err != nil {
		return err
	}

	for _, share := range shares {
		jsonShare, err := json.Marshal(share)
		if err != nil {
			panic(err)
		}

		filename := fmt.Sprintf("%s/share-%d.json", *outDirPtr, share.ID)
		if err := ioutil.WriteFile(filename, jsonShare, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", filename, err)
		}
		fmt.Printf("Share written to: %s\n", filename)
	}

	fmt.Println("Complete.")
	return nil
}

func doRecover() error {
	recoverCmd := flag.NewFlagSet("split", flag.ExitOnError)
	sharePathsPtr := recoverCmd.String("share-paths", "", "Comma-separated list of share files")
	outPathPtr := recoverCmd.String("out-path", "", "file path to create with the secret")
	recoverCmd.Parse(os.Args[2:])

	sharePaths := strings.Split(*sharePathsPtr, ",")
	shares := make([]*adss.SecretShare, len(sharePaths))
	for i, sharePath := range sharePaths {
		bytes, err := ioutil.ReadFile(sharePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", sharePath, err)
		}

		var share adss.SecretShare
		err = json.Unmarshal(bytes, &share)
		if err != nil {
			return fmt.Errorf("unmarshal %s: %w", sharePath, err)
		}

		shares[i] = &share
	}

	secret, validShares, err := adss.Recover(shares)
	if err != nil {
		return err
	}

	if len(validShares) < len(shares) {
		for i, inShare := range shares {
			found := false
			for _, validShare := range validShares {
				if inShare.Equal(validShare) {
					found = true
					break
				}
			}

			if !found {
				fmt.Fprintf(os.Stderr, "WARN: Invalid share at %s\n", sharePaths[i])
			}
		}
	}

	// If a filepath is provided store the secret there, otherwise
	// we print it to stdout in base64.
	if *outPathPtr != "" {
		if err := ioutil.WriteFile(*outPathPtr, secret, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", *outPathPtr, err)
		}
		fmt.Printf("Secret written to: %s\n", *outPathPtr)
	} else {
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(secret))
	}

	return nil
}

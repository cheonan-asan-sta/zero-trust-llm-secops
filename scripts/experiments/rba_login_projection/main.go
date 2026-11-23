// Project the publisher's pinned RBA export into separate observations and ATO truth.
package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const archiveSHA = "ca1d974e97aebfb30878a613f4ca5c793860a98ba2acb5185c9bc610d7432a33"
const probeSHA = "a3fd499deae8427f5558b57b06f45ad1af34ec9219b1041ed874b63364044f40"

var expectedHeader = []string{"index", "Login Timestamp", "User ID", "Round-Trip Time [ms]", "IP Address", "Country", "Region", "City", "ASN", "User Agent String", "Browser Name and Version", "OS Name and Version", "Device Type", "Login Successful", "Is Attack IP", "Is Account Takeover"}

func digest(reader io.Reader) (string, error) {
	hash := sha256.New()
	_, err := io.Copy(hash, reader)
	return hex.EncodeToString(hash.Sum(nil)), err
}

func probeReferences(path string) (map[string]bool, error) {
	body, err := os.ReadFile(path)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(body)) != probeSHA {
		return nil, fmt.Errorf("unexpected development probe receipt")
	}
	var receipt struct {
		References []string `json:"development_probe_user_references"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		return nil, err
	}
	probed := make(map[string]bool, len(receipt.References))
	for _, reference := range receipt.References {
		probed[reference] = true
	}
	return probed, nil
}

func publisherBit(value string) (byte, error) {
	switch strings.ToLower(value) {
	case "true":
		return '1', nil
	case "false":
		return '0', nil
	default:
		return 0, fmt.Errorf("invalid publisher Boolean")
	}
}

func project(in io.Reader, observations, truth *bufio.Writer, probed map[string]bool) error {
	csvDigest := sha256.New()
	reader := csv.NewReader(io.TeeReader(in, csvDigest))
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil || !slices.Equal(header, expectedHeader) {
		return fmt.Errorf("unexpected publisher CSV header")
	}
	var ordinal, reserved int
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid publisher CSV record at row %d", ordinal+1)
		}
		ordinal++
		userDigest := sha256.Sum256([]byte("rba-user:" + row[2]))
		if binary.BigEndian.Uint64(userDigest[:8])%100 < 85 {
			continue
		}
		user := hex.EncodeToString(userDigest[:])
		if probed[user] {
			continue
		}
		if _, err := strconv.ParseInt(row[2], 10, 64); err != nil {
			return fmt.Errorf("unparseable reserved account at row %d", ordinal)
		}
		reserved++
		observed, err := publisherBit(row[13])
		if err != nil {
			return err
		}
		label, err := publisherBit(row[15])
		if err != nil {
			return err
		}
		client := "-"
		if row[4] != "" {
			hash := sha256.Sum256([]byte("rba-captured-ip:" + row[4]))
			client = hex.EncodeToString(hash[:])
		}
		if _, err := fmt.Fprintf(observations, "%d\t%s\t%s\t%s\t%c\n", ordinal, row[1], user, client, observed); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(truth, "%d\t%c\n", ordinal, label); err != nil {
			return err
		}
	}
	if ordinal != 31269264 || reserved != 2575003 || fmt.Sprintf("%x", csvDigest.Sum(nil)) != "001f3589595821519b53428aee656b4458e43d8f5b4b9beb6ec2bed8f2209067" {
		return fmt.Errorf("publisher CSV or reserved population differs")
	}
	return nil
}

func run(archivePath, probePath, output string) error {
	probe, err := probeReferences(probePath)
	if err != nil {
		return err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	stat, err := archive.Stat()
	if err != nil || stat.Size() != 1093700330 {
		return fmt.Errorf("unexpected publisher archive size")
	}
	actualSHA, err := digest(archive)
	if err != nil || actualSHA != archiveSHA {
		return fmt.Errorf("unexpected publisher archive digest")
	}
	zipped, err := zip.NewReader(archive, stat.Size())
	if err != nil {
		return err
	}
	var member *zip.File
	for _, file := range zipped.File {
		if file.Name == "rba-dataset.csv" {
			if member != nil || file.CRC32 != 0x864184c1 || file.UncompressedSize64 != 9052907531 {
				return fmt.Errorf("unexpected publisher member")
			}
			member = file
		}
	}
	if member == nil {
		return fmt.Errorf("publisher member unavailable")
	}
	stream, err := member.Open()
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := os.Mkdir(output, 0700); err != nil {
		return err
	}
	observations, err := os.Create(filepath.Join(output, "observations.tsv"))
	if err != nil {
		return err
	}
	defer observations.Close()
	truth, err := os.Create(filepath.Join(output, "truth.tsv"))
	if err != nil {
		return err
	}
	defer truth.Close()
	obsWriter, truthWriter := bufio.NewWriterSize(observations, 1<<18), bufio.NewWriterSize(truth, 1<<18)
	if err := project(stream, obsWriter, truthWriter, probe); err != nil {
		return err
	}
	if err := obsWriter.Flush(); err != nil {
		return err
	}
	if err := truthWriter.Flush(); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "completed"), []byte(archiveSHA+"\n"), 0600)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go run main.go <rba-zip> <probe-receipt> <new-output>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

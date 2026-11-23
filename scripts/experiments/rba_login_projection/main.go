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
	"flag"
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

type cohort struct {
	observations, truth *bufio.Writer
	rows                int
}

func featureKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "unknown" || value == "other" || value == "-" {
		return "-"
	}
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:12])
}

func clientFamily(value string) string {
	for index, char := range value {
		if char >= '0' && char <= '9' {
			return strings.TrimSpace(value[:index])
		}
	}
	return value
}

func cohortName(bucket uint64, mode string) string {
	if mode == "confirmation" {
		if bucket < 20 {
			return "confirmation"
		}
		return ""
	}
	if bucket >= 85 {
		return "reviewed"
	}
	if mode == "environment" && bucket >= 70 {
		return "holdout"
	}
	return ""
}

func project(in io.Reader, cohorts map[string]*cohort, probed map[string]bool, mode string) error {
	csvDigest := sha256.New()
	reader := csv.NewReader(io.TeeReader(in, csvDigest))
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil || !slices.Equal(header, expectedHeader) {
		return fmt.Errorf("unexpected publisher CSV header")
	}
	var ordinal int
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
		bucket := binary.BigEndian.Uint64(userDigest[:8]) % 100
		name := cohortName(bucket, mode)
		if name == "" {
			continue
		}
		output := cohorts[name]
		user := hex.EncodeToString(userDigest[:])
		if probed[user] {
			continue
		}
		if _, err := strconv.ParseInt(row[2], 10, 64); err != nil {
			return fmt.Errorf("unparseable reserved account at row %d", ordinal)
		}
		output.rows++
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
		if _, err := fmt.Fprintf(output.observations, "%d\t%s\t%s\t%s\t%c", ordinal, row[1], user, client, observed); err != nil {
			return err
		}
		if mode != "basic" {
			if _, err := fmt.Fprintf(output.observations, "\t%s\t%s\t%s\t%s\t%s", featureKey(row[5]), featureKey(row[8]), featureKey(clientFamily(row[10])), featureKey(clientFamily(row[11])), featureKey(row[12])); err != nil {
				return err
			}
		}
		if err := output.observations.WriteByte('\n'); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output.truth, "%d\t%c\n", ordinal, label); err != nil {
			return err
		}
	}
	if ordinal != 31269264 || fmt.Sprintf("%x", csvDigest.Sum(nil)) != "001f3589595821519b53428aee656b4458e43d8f5b4b9beb6ec2bed8f2209067" {
		return fmt.Errorf("publisher CSV or reserved population differs")
	}
	if (mode != "confirmation" && cohorts["reviewed"].rows != 2575003) || (mode == "environment" && cohorts["holdout"].rows != 2572078) || (mode == "confirmation" && cohorts["confirmation"].rows == 0) {
		return fmt.Errorf("unexpected selected population")
	}
	return nil
}

func run(archivePath, probePath, output string, mode string) error {
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
	cohorts := make(map[string]*cohort)
	names := []string{"reviewed"}
	if mode == "environment" {
		names = append(names, "holdout")
	}
	if mode == "confirmation" {
		names = []string{"confirmation"}
	}
	for _, name := range names {
		directory := output
		if mode != "basic" {
			directory = filepath.Join(output, name)
			if err := os.Mkdir(directory, 0700); err != nil {
				return err
			}
		}
		observations, err := os.Create(filepath.Join(directory, "observations.tsv"))
		if err != nil {
			return err
		}
		defer observations.Close()
		truth, err := os.Create(filepath.Join(directory, "truth.tsv"))
		if err != nil {
			return err
		}
		defer truth.Close()
		cohorts[name] = &cohort{observations: bufio.NewWriterSize(observations, 1<<18), truth: bufio.NewWriterSize(truth, 1<<18)}
	}
	if err := project(stream, cohorts, probe, mode); err != nil {
		return err
	}
	for _, result := range cohorts {
		if err := result.observations.Flush(); err != nil {
			return err
		}
		if err := result.truth.Flush(); err != nil {
			return err
		}
	}
	if mode == "confirmation" {
		report, err := json.Marshal(map[string]any{"bucket_first": 0, "bucket_last": 19, "rows": cohorts["confirmation"].rows, "archive_sha256": archiveSHA, "probe_sha256": probeSHA})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, "population.json"), report, 0600); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(output, "completed"), []byte(archiveSHA+"\n"), 0600)
}

func main() {
	environment := flag.Bool("environment", false, "include environment changes for reviewed and withheld users")
	confirmation := flag.Bool("confirmation", false, "project untouched account buckets 0 through 19")
	flag.Parse()
	if flag.NArg() != 3 || (*environment && *confirmation) {
		fmt.Fprintln(os.Stderr, "usage: go run main.go [--environment | --confirmation] <rba-zip> <probe-receipt> <new-output>")
		os.Exit(2)
	}
	mode := "basic"
	if *environment {
		mode = "environment"
	} else if *confirmation {
		mode = "confirmation"
	}
	if err := run(flag.Arg(0), flag.Arg(1), flag.Arg(2), mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

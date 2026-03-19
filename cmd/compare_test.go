package cmd

import (
	"encoding/csv"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

func TestPct(t *testing.T) {
	cases := []struct {
		num, denom int
		want       float64
	}{
		{50, 100, 50.0},
		{1, 3, 100.0 / 3.0},
		{0, 100, 0.0},
		{0, 0, 0.0},
		{100, 100, 100.0},
	}
	for _, tc := range cases {
		got := pct(tc.num, tc.denom)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("pct(%d, %d) = %f, want %f", tc.num, tc.denom, got, tc.want)
		}
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]int{"charlie": 3, "alpha": 1, "bravo": 2}
	got := sortedKeys(m)
	want := []string{"alpha", "bravo", "charlie"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sortedKeys[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Empty map
	empty := sortedKeys(map[string]bool{})
	if len(empty) != 0 {
		t.Errorf("expected empty slice for empty map, got %v", empty)
	}
}

func TestWriteConfusionCSV(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "confusion.csv")

	confusion := map[string]map[string]int{
		"firefox": {"firefox": 8, "chrome": 2},
		"chrome":  {"chrome": 5, "<unlabeled>": 1},
	}
	truthLabels := []string{"chrome", "firefox"}
	testLabels := []string{"<unlabeled>", "chrome", "firefox"}

	writeConfusionCSV(csvPath, truthLabels, testLabels, confusion)

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 2 data rows
	if len(records) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(records))
	}

	// Header: ground_truth, <unlabeled>, chrome, firefox
	if records[0][0] != "ground_truth" {
		t.Errorf("header[0] = %q, want %q", records[0][0], "ground_truth")
	}

	// chrome row: chrome, 1, 5, 0
	if records[1][0] != "chrome" || records[1][1] != "1" || records[1][2] != "5" {
		t.Errorf("chrome row = %v, want [chrome 1 5 0]", records[1])
	}

	// firefox row: firefox, 0, 2, 8
	if records[2][0] != "firefox" || records[2][2] != "2" || records[2][3] != "8" {
		t.Errorf("firefox row = %v, want [firefox 0 2 8]", records[2])
	}
}

func TestNextEPB(t *testing.T) {
	dir := t.TempDir()
	pcapngPath := filepath.Join(dir, "test.pcapng")

	w, err := pcapng.NewWriter(pcapngPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	w.WritePacket(1000000, []byte{0x45, 0x00}, 2, "s=0,proc=test")
	w.WritePacket(2000000, []byte{0x45, 0x01}, 2, "s=1,proc=other")
	w.Close()

	r, err := pcapng.NewReader(pcapngPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	b1 := nextEPB(r)
	if b1 == nil {
		t.Fatal("expected first EPB")
	}
	if b1.Label() != "test" {
		t.Errorf("first label = %q, want %q", b1.Label(), "test")
	}

	b2 := nextEPB(r)
	if b2 == nil {
		t.Fatal("expected second EPB")
	}
	if b2.Label() != "other" {
		t.Errorf("second label = %q, want %q", b2.Label(), "other")
	}

	b3 := nextEPB(r)
	if b3 != nil {
		t.Error("expected nil after last EPB")
	}
}

func TestCompareCSVOutput(t *testing.T) {
	dir := t.TempDir()

	// Create truth file: 3 packets labeled A, A, B
	truthPath := filepath.Join(dir, "truth.pcapng")
	tw, err := pcapng.NewWriter(truthPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	pktA := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8}
	pktB := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2, 1, 1, 1, 1}
	pktC := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 3, 8, 8, 4, 4}
	tw.WritePacket(1000000, pktA, uint32(len(pktA)), "s=0,proc=appA")
	tw.WritePacket(2000000, pktB, uint32(len(pktB)), "s=0,proc=appA")
	tw.WritePacket(3000000, pktC, uint32(len(pktC)), "s=1,proc=appB")
	tw.Close()

	// Create test file: same packets but second is mislabeled
	testPath := filepath.Join(dir, "test.pcapng")
	rw, err := pcapng.NewWriter(testPath, pcapng.LinkTypeRawIPv4, 1500)
	if err != nil {
		t.Fatal(err)
	}
	rw.WritePacket(1000000, pktA, uint32(len(pktA)), "s=0,proc=appA")
	rw.WritePacket(2000000, pktB, uint32(len(pktB)), "s=0,proc=appX") // mislabeled
	rw.WritePacket(3000000, pktC, uint32(len(pktC)), "s=1,proc=appB")
	rw.Close()

	csvPath := filepath.Join(dir, "confusion.csv")
	runCompare([]string{"-truth", truthPath, "-test", testPath, "-csv", csvPath})

	// Verify CSV was written
	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("open CSV: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Should have header + rows for each truth label
	if len(records) < 2 {
		t.Fatalf("expected at least 2 CSV rows, got %d", len(records))
	}
	if records[0][0] != "ground_truth" {
		t.Errorf("CSV header[0] = %q, want %q", records[0][0], "ground_truth")
	}
}

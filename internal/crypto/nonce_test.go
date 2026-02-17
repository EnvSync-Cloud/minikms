package crypto

import "testing"

func TestCheckEncryptionCount(t *testing.T) {
	tests := []struct {
		name           string
		currentCount   int64
		maxEncryptions int64
		wantStatus     KeyStatus
		wantErr        bool
	}{
		{"active - zero count", 0, 1000, KeyStatusActive, false},
		{"active - below 90%", 899, 1000, KeyStatusActive, false},
		{"rotate pending - at 90%", 900, 1000, KeyStatusRotatePending, false},
		{"rotate pending - between 90-99%", 950, 1000, KeyStatusRotatePending, false},
		{"rotate pending - at 99%", 999, 1000, KeyStatusRotatePending, false},
		{"retired - at 100%", 1000, 1000, KeyStatusRetired, false},
		{"retired - over 100%", 1500, 1000, KeyStatusRetired, false},
		{"negative count error", -1, 1000, "", true},
		{"zero max error", 0, 0, "", true},
		{"negative max error", 0, -1, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := CheckEncryptionCount(tt.currentCount, tt.maxEncryptions)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && status != tt.wantStatus {
				t.Errorf("got %q, want %q", status, tt.wantStatus)
			}
		})
	}
}

func TestDefaultMaxEncryptions(t *testing.T) {
	expected := int64(1 << 30)
	if DefaultMaxEncryptions != expected {
		t.Errorf("DefaultMaxEncryptions = %d, want %d", DefaultMaxEncryptions, expected)
	}
}

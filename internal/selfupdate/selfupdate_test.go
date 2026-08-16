package selfupdate

import "testing"

func TestFindAsset(t *testing.T) {
	t.Parallel()

	assets := []Asset{
		{Name: "pindrop_0.1.0_linux_amd64.tar.gz"},
		{Name: "pindrop_0.1.0_darwin_arm64.tar.gz"},
		{Name: "pindrop_0.1.0_windows_amd64.zip"},
	}

	got := findAsset(assets, "darwin", "arm64")
	if got == nil || got.Name != "pindrop_0.1.0_darwin_arm64.tar.gz" {
		t.Fatalf("findAsset(darwin, arm64) = %#v, want darwin arm64 asset", got)
	}

	if findAsset(assets, "freebsd", "amd64") != nil {
		t.Fatal("findAsset(freebsd, amd64) should be nil")
	}
}

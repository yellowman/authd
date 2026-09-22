package identity

import (
	"reflect"
	"testing"
)

func TestEffectivePermissionsUnion(t *testing.T) {
	got := EffectivePermissions([]string{"viewer", "operator"}, map[string][]string{
		"viewer":   {"bdcmaps.map.read", "bdcmaps.site.read"},
		"operator": {"bdcmaps.site.read", "bdcmaps.site.write"},
	})
	want := []string{"bdcmaps.map.read", "bdcmaps.site.read", "bdcmaps.site.write"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

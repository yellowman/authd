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

func TestPermissionNamesCannotShadowIdentityScopes(t *testing.T) {
	for _, name := range []string{"openid", "profile", "email", "groups", "roles", "offline_access"} {
		if ValidatePermissionName(name, "") == nil {
			t.Fatalf("reserved permission accepted: %s", name)
		}
		if ValidateName(name, "") != nil {
			t.Fatalf("role names must not be confused with permission names: %s", name)
		}
	}
	for _, name := range []string{"system.admin", "billing.email.send", "reports.export"} {
		if err := ValidatePermissionName(name, ""); err != nil {
			t.Fatal(err)
		}
	}
}

package oidc

import (
	"slices"
	"strings"
)

type consentScopeNode struct {
	Label, Scope, Description string
	Count                     int
	Open                      bool
	Children                  []*consentScopeNode
}

type consentComparison struct {
	HasPrior, HasChanges                          bool
	ApprovedAt                                    string
	NewScopes, ApprovedScopes, NotRequestedScopes []*consentScopeNode
	NewClaims, ApprovedClaims, NotRequestedClaims []string
	NewCount, ApprovedCount, NotRequestedCount    int
}

func compareConsent(scopes, claims []string, previous ConsentApproval) *consentComparison {
	view := &consentComparison{HasPrior: !previous.ApprovedAt.IsZero()}
	var previousScopes, previousClaims []string
	if view.HasPrior {
		previousScopes = previous.Scopes
		previousClaims = consentClaimNames(ClaimSelection{IDToken: previous.IDTokenClaims, UserInfo: previous.UserInfoClaims})
		view.ApprovedAt = previous.ApprovedAt.UTC().Format("Jan 2, 2006, 15:04 UTC")
	}
	added, unchanged, omitted := consentDiff(scopes, previousScopes)
	view.NewScopes = groupConsentScopes(added, true)
	view.ApprovedScopes = groupConsentScopes(unchanged, false)
	view.NotRequestedScopes = groupConsentScopes(omitted, false)
	view.NewClaims, view.ApprovedClaims, view.NotRequestedClaims = consentDiff(claims, previousClaims)
	view.NewCount = len(added) + len(view.NewClaims)
	view.ApprovedCount = len(unchanged) + len(view.ApprovedClaims)
	view.NotRequestedCount = len(omitted) + len(view.NotRequestedClaims)
	view.HasChanges = view.NewCount > 0 || view.NotRequestedCount > 0
	return view
}

func consentDiff(current, previous []string) (added, unchanged, omitted []string) {
	currentSet, previousSet := map[string]bool{}, map[string]bool{}
	for _, name := range current {
		currentSet[name] = true
	}
	for _, name := range previous {
		previousSet[name] = true
	}
	for name := range currentSet {
		if previousSet[name] {
			unchanged = append(unchanged, name)
		} else {
			added = append(added, name)
		}
	}
	for name := range previousSet {
		if !currentSet[name] {
			omitted = append(omitted, name)
		}
	}
	slices.Sort(added)
	slices.Sort(unchanged)
	slices.Sort(omitted)
	return
}

func groupConsentScopes(scopes []string, open bool) []*consentScopeNode {
	root := &consentScopeNode{}
	index := map[string]*consentScopeNode{}
	for _, scope := range scopes {
		parent, path := root, ""
		for i, label := range strings.Split(scope, ".") {
			if i > 0 {
				path += "."
			}
			path += label
			node := index[path]
			if node == nil {
				node = &consentScopeNode{Label: label, Open: open}
				index[path] = node
				parent.Children = append(parent.Children, node)
			}
			node.Count++
			parent = node
		}
		parent.Scope = scope
		if identityScopes[scope] {
			parent.Description = ScopeDescription(scope)
		}
	}
	var sortNodes func([]*consentScopeNode)
	sortNodes = func(nodes []*consentScopeNode) {
		slices.SortFunc(nodes, func(a, b *consentScopeNode) int { return strings.Compare(a.Label, b.Label) })
		for _, node := range nodes {
			sortNodes(node.Children)
		}
	}
	sortNodes(root.Children)
	return root.Children
}

package iptables

import (
	"testing"
)

func TestIptutil_Append(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	rule := Rule{"nat", "PREROUTING", []string{"-p", "tcp", "--dport", "80", "-j", "ACCEPT"}}

	err = iptutil.Append(rule)
	if err != nil {
		t.Errorf("Failed to append rule: %v", err)
	}
}

func TestIptutil_InsertUnique(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	rule := Rule{"nat", "PREROUTING", []string{"-p", "all", "-d", "10.244.15.0/16", "-j", "DNAT", "--to-destination", "169.254.96.16:40505"}}

	err = iptutil.InsertUnique(rule, 1)
	if err != nil {
		t.Errorf("Failed to insert unique rule: %v", err)
	}
}

func TestIptutil_Delete(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	rule := Rule{"filter", "INPUT", []string{"-p", "all", "--dport", "80", "-j", "ACCEPT"}}

	err = iptutil.Delete(rule)
	if err != nil {
		t.Errorf("Failed to delete rule: %v", err)
	}
}

func TestIptutil_Exists(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	rule := Rule{"filter", "INPUT", []string{"-p", "tcp", "--dport", "80", "-j", "ACCEPT"}}

	exists, err := iptutil.Exists(rule)
	if err != nil {
		t.Errorf("Failed to check rule existence: %v", err)
	}
	if !exists {
		t.Errorf("Rule does not exist")
	}
}

func TestIptutil_List(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	rules, err := iptutil.List("filter", "INPUT")
	if err != nil {
		t.Errorf("Failed to list rules: %v", err)
	}
	if len(rules) == 0 {
		t.Errorf("No rules found")
	}
}

func TestIptutil_ClearChain(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	err = iptutil.ClearChain("filter", "INPUT")
	if err != nil {
		t.Errorf("Failed to clear chain: %v", err)
	}
}

func TestIptutil_NewChain(t *testing.T) {
	iptutil, err := New()
	if err != nil {
		t.Errorf("Failed to create Iptutil: %v", err)
	}

	err = iptutil.NewChain("nat", "EDGEMESH")
	if err != nil {
		t.Errorf("Failed to create chain: %v", err)
	}
}

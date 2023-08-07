package iptables

import (
	"github.com/coreos/go-iptables/iptables"
	klog "k8s.io/klog/v2"
)

// rule represents an iptables rule.
type Rule struct {
	Table string
	Chain string
	Spec  []string
}

// IptOp iptable Operation include all the operation to interact with iptables
type IptOp interface {
	// Append insert rules in the table
	Append(rule Rule) error

	// InsertUnique insert single rule into the position of the table
	InsertUnique(rule Rule, pos int) error

	// Delete rule from the table
	Delete(rule Rule) error

	// Exists check if the rules are right
	Exists(rule Rule) (bool, error)

	// List show all the rules from the chain
	List(table string, chain string) ([]string, error)

	// ClearChain clear the chain
	ClearChain(table string, chain string) error

	// NewChain create a new chain
	NewChain(table string, chain string) error
}

// Iptutil iptable tools to control the rules
type Iptutil struct {
	// coreos/go-iptables added  contains filtered or unexported fields
	ipt *iptables.IPTables

	// rules need to append, and it should be a queue to store the respec
	ruleSet []Rule
}

// New init operator to control ipatbles
func New() (IptOp, error) {
	// init ipatbles operator for ipv4 rules
	// TODO: add IPV6 support
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))

	if err != nil {
		klog.Errorf("Failed to create iptables operator : %v", err)
		return nil, err
	}
	klog.Infof("create iptables operator success")

	return &Iptutil{ipt, []Rule{}}, nil
}

func (iptutil *Iptutil) Append(rule Rule) error {
	// check if the rule is in the table
	ok, err := iptutil.Exists(rule)
	// if there is no such rule then add it
	if err == nil && !ok {
		err = iptutil.ipt.AppendUnique(rule.Table, rule.Chain, rule.Spec...)
		klog.Infof("this rule is not exist, start to insert it")
	}
	if err != nil {
		klog.Errorf("error on iptables.AppendUnique in table %v on chain %v for rule %v, err ", rule.Table, rule.Chain, rule.Spec, err)
		return err
	}
	klog.Infof("iptables.AppendUnique succeeded in table %v on chain %v for rule %v", rule.Table, rule.Chain, rule.Spec)

	return nil
}

func (iptutil *Iptutil) InsertUnique(rule Rule, pos int) error {
	exists, err := iptutil.Exists(rule)
	// if there is no such rule then add it in the special position
	if err == nil && !exists {
		err = iptutil.ipt.Insert(rule.Table, rule.Chain, pos, rule.Spec...)
		klog.Infof("this rule is not exist, start to insert it on the position %v", pos)
	}
	if err != nil {
		klog.Errorf("error on iptables.AppendUnique in table %v on chain %v  at position %v for rule %v, err ", rule.Table, rule.Chain, pos, rule.Spec, err)
		return err
	}
	klog.Infof("iptables.AppendUnique succeeded in table %v on chain %v at position %v for rule %v", rule.Table, rule.Chain, pos, rule.Spec)
	return nil
}

func (iptutil *Iptutil) Delete(rule Rule) error {
	// delete the rule
	err := iptutil.ipt.DeleteIfExists(rule.Table, rule.Chain, rule.Spec...)
	if err != nil {
		klog.Errorf("error on iptables.Delete in table %v on chain %v for rule %v, err ", rule.Table, rule.Chain, rule.Spec, err)
		return err
	}
	klog.Infof("iptables.Delete succeeded in table %v on chain %v for rule %v", rule.Table, rule.Chain, rule.Spec)
	return nil
}

func (iptutil *Iptutil) Exists(rule Rule) (bool, error) {
	// check if the rule exist in the table
	exists, err := iptutil.ipt.Exists(rule.Table, rule.Chain, rule.Spec...)
	if err == nil && !exists {
		klog.Infof("rule is not exist in table %v on chain %v", rule.Table, rule.Chain, rule.Spec)
		return false, nil
	}
	if err != nil {
		klog.Errorf("error on iptables.Exists in table %v on chain %v for rule %v, err ", rule.Table, rule.Chain, rule.Spec, err)
		return false, err
	}
	klog.Infof("iptables rules exist in table %v on chain %v", rule.Table, rule.Chain)
	return true, nil
}

func (iptutil *Iptutil) List(table string, chain string) ([]string, error) {
	// get the rule from the table/chain
	rules, err := iptutil.ipt.List(table, chain)
	if err != nil {
		klog.Errorf("error on iptables.List in table %v on chain %v  err ", table, chain, err)
		return nil, err
	}
	klog.Infof("iptables.List succeeded, in table %v on chain %v get rules %v", table, chain, rules)
	return rules, nil
}

func (iptutil *Iptutil) ClearChain(table string, chain string) error {
	// clear the chain
	err := iptutil.ipt.ClearAndDeleteChain(table, chain)
	if err != nil {
		klog.Errorf("error on iptables.ClearAndDeleteChain in table %v on chain %v  err ", table, chain, err)
		return err
	}
	klog.Infof("iptables.ClearAndDeleteChain succeeded, in table %v on chain %v ", table, chain)
	return nil
}

func (iptutil *Iptutil) NewChain(table string, chain string) error {
	// check if the chain exist
	exists, err := iptutil.ipt.ChainExists(table, chain)
	if err == nil && !exists {
		err = iptutil.ipt.NewChain(table, chain)
		klog.Infof("there is no such chain existv, now start to Newchain")
	}
	if err != nil {
		klog.Errorf("error on iptables.NewChain in table %v for chain %v  err ", table, chain, err)
		return err
	}
	klog.Infof("iptables.NewChain succeeded, in table %v for chain %v ", table, chain)
	return nil
}

// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"strconv"
	"strings"
	"sync"

	"github.com/team-seaweed/gauth/rbac"
	"github.com/team-seaweed/gauth/util"
)

type (
	PolicyOp int
)

const (
	PolicyAdd PolicyOp = iota
	PolicyRemove
)

const DefaultSep = ","

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
func (model *Model) BuildIncrementalRoleLinks(rmMap map[string]rbac.RoleManager, op PolicyOp, sec string, ptype string, rules [][]string) error {
	if sec == "g" {
		ast, ok := model.GetAstBySecPType(sec, ptype)
		if !ok {
			return nil
		}
		return ast.buildIncrementalRoleLinks(rmMap[ptype], op, rules)
	}
	return nil
}

// BuildRoleLinks initializes the roles in RBAC.
func (model *Model) BuildRoleLinks(rmMap map[string]rbac.RoleManager) (err error) {
	model.PrintPolicy()
	amap, ok := model.GetKey("g")
	if !ok {
		return nil
	}
	amap.Range(func(key, value interface{}) bool {
		rm := rmMap[key.(string)]
		err = value.(*Assertion).buildRoleLinks(rm)
		if err != nil {
			return false
		}
		return true
	})
	return nil
}

// PrintPolicy prints the policy to log.
func (model *Model) PrintPolicy() {
	if !model.GetLogger().IsEnabled() {
		return
	}

	policy := make(map[string][][]string)
	amap, ok := model.GetKey("p")
	if !ok {
		return
	}
	amap.Range(func(key1, value1 interface{}) bool {
		key := key1.(string)
		ast := value1.(*Assertion)
		value, found := policy[key]
		if found {
			value = append(value, ast.Policy...)
			policy[key] = value
		} else {
			policy[key] = ast.Policy
		}

		return true
	})
	gmap, ok := model.GetKey("g")
	if !ok {
		return
	}
	gmap.Range(func(key1, value1 interface{}) bool {
		key := key1.(string)
		ast := value1.(*Assertion)
		value, found := policy[key]
		if found {
			value = append(value, ast.Policy...)
			policy[key] = value
		} else {
			policy[key] = ast.Policy
		}

		return true
	})

	model.GetLogger().LogPolicy(policy)
}

// ClearPolicy clears all current policy.
func (model *Model) ClearPolicy() {
	amap, ok := model.GetKey("p")
	if !ok {
		return
	}
	amap.Range(func(key1, value1 interface{}) bool {
		ast := value1.(*Assertion)
		ast.Policy = nil
		ast.PolicyMap = new(sync.Map)
		return true
	})
	gmap, ok := model.GetKey("g")
	if !ok {
		return
	}
	gmap.Range(func(key1, value1 interface{}) bool {
		ast := value1.(*Assertion)
		ast.Policy = nil
		ast.PolicyMap = new(sync.Map)
		return true
	})
}

// GetPolicy gets all rules in a policy.
func (model *Model) GetPolicy(sec string, ptype string) [][]string {
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return nil
	}
	return ast.Policy
}

// GetFilteredPolicy gets rules based on field filters from a policy.
func (model *Model) GetFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) [][]string {
	res := [][]string{}
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return res
	}
	for _, rule := range ast.Policy {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			res = append(res, rule)
		}
	}

	return res
}

// HasPolicy determines whether a model has the specified policy rule.
func (model *Model) HasPolicy(sec string, ptype string, rule []string) bool {
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return ok
	}
	_, ok = ast.PolicyMap.Load(strings.Join(rule, DefaultSep))
	return ok
}

// HasPolicies determines whether a model has any of the specified policies. If one is found we return true.
func (model *Model) HasPolicies(sec string, ptype string, rules [][]string) bool {
	for i := 0; i < len(rules); i++ {
		if model.HasPolicy(sec, ptype, rules[i]) {
			return true
		}
	}

	return false
}

// AddPolicy adds a policy rule to the model.
func (model *Model) AddPolicy(sec string, ptype string, rule []string) {

	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return
	}

	assertion := ast
	assertion.Policy = append(assertion.Policy, rule)
	assertion.PolicyMap.Store(strings.Join(rule, DefaultSep), len(ast.Policy)-1)

	if sec == "p" && assertion.priorityIndex >= 0 {
		if idxInsert, err := strconv.Atoi(rule[assertion.priorityIndex]); err == nil {
			i := len(assertion.Policy) - 1
			for ; i > 0; i-- {
				idx, err := strconv.Atoi(assertion.Policy[i-1][assertion.priorityIndex])
				if err != nil {
					break
				}
				if idx > idxInsert {
					assertion.Policy[i] = assertion.Policy[i-1]
					pvalue, ok := assertion.PolicyMap.Load(strings.Join(assertion.Policy[i-1], DefaultSep))
					if !ok {
						assertion.PolicyMap.Store(strings.Join(assertion.Policy[i-1], DefaultSep), 1)
					}
					assertion.PolicyMap.Store(strings.Join(assertion.Policy[i-1], DefaultSep), pvalue.(int)+1)
				} else {
					break
				}
			}
			assertion.Policy[i] = rule
			assertion.PolicyMap.Store(strings.Join(rule, DefaultSep), i)
		}
	}
}

// AddPolicies adds policy rules to the model.
func (model *Model) AddPolicies(sec string, ptype string, rules [][]string) {
	_ = model.AddPoliciesWithAffected(sec, ptype, rules)
}

// AddPoliciesWithAffected adds policy rules to the model, and returns effected rules.
func (model *Model) AddPoliciesWithAffected(sec string, ptype string, rules [][]string) [][]string {
	var effected [][]string
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return effected
	}
	for _, rule := range rules {
		hashKey := strings.Join(rule, DefaultSep)
		_, ok = ast.PolicyMap.Load(hashKey)
		if ok {
			continue
		}
		effected = append(effected, rule)
		model.AddPolicy(sec, ptype, rule)
	}
	return effected
}

// RemovePolicy removes a policy rule from the model.
// Deprecated: Using AddPoliciesWithAffected instead.
func (model *Model) RemovePolicy(sec string, ptype string, rule []string) bool {
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return ok
	}
	ivalue, ok := ast.PolicyMap.Load(strings.Join(rule, DefaultSep))
	if !ok {
		return false
	}
	index := ivalue.(int)
	ast.Policy = append(ast.Policy[:index], ast.Policy[index+1:]...)
	ast.PolicyMap.Delete(strings.Join(rule, DefaultSep))
	for i := index; i < len(ast.Policy); i++ {
		ast.PolicyMap.Store(strings.Join(ast.Policy[i], DefaultSep), i)
	}

	return true
}

// UpdatePolicy updates a policy rule from the model.
func (model *Model) UpdatePolicy(sec string, ptype string, oldRule []string, newRule []string) bool {
	oldPolicy := strings.Join(oldRule, DefaultSep)
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return ok
	}
	ivalue, ok := ast.PolicyMap.Load(oldPolicy)
	if !ok {
		return false
	}
	index := ivalue.(int)
	ast.Policy[index] = newRule
	ast.PolicyMap.Delete(oldPolicy)
	ast.PolicyMap.Store(strings.Join(newRule, DefaultSep), index)
	return true
}

// UpdatePolicies updates a policy rule from the model.
func (model *Model) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) bool {
	rollbackFlag := false
	// index -> []{oldIndex, newIndex}
	modifiedRuleIndex := make(map[int][]int)
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return ok
	}
	// rollback
	defer func() {
		if rollbackFlag {
			for index, oldNewIndex := range modifiedRuleIndex {
				ast.Policy[index] = oldRules[oldNewIndex[0]]
				oldPolicy := strings.Join(oldRules[oldNewIndex[0]], DefaultSep)
				newPolicy := strings.Join(newRules[oldNewIndex[1]], DefaultSep)
				ast.PolicyMap.Delete(newPolicy)
				ast.PolicyMap.Store(oldPolicy, index)
			}
		}
	}()

	newIndex := 0
	for oldIndex, oldRule := range oldRules {
		oldPolicy := strings.Join(oldRule, DefaultSep)
		ivalue, ok := ast.PolicyMap.Load(oldPolicy)
		if !ok {
			rollbackFlag = true
			return false
		}
		index := ivalue.(int)
		ast.Policy[index] = newRules[newIndex]
		ast.PolicyMap.Delete(oldPolicy)
		ast.PolicyMap.Store(strings.Join(newRules[newIndex], DefaultSep), index)
		modifiedRuleIndex[index] = []int{oldIndex, newIndex}
		newIndex++
	}

	return true
}

// RemovePolicies removes policy rules from the model.
func (model *Model) RemovePolicies(sec string, ptype string, rules [][]string) bool {
	effected := model.RemovePoliciesWithEffected(sec, ptype, rules)
	return len(effected) != 0
}

// RemovePoliciesWithEffected removes policy rules from the model, and returns effected rules.
func (model *Model) RemovePoliciesWithEffected(sec string, ptype string, rules [][]string) [][]string {
	var effected [][]string
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return effected
	}
	for _, rule := range rules {
		iValue, ok := ast.PolicyMap.Load(strings.Join(rule, DefaultSep))
		if !ok {
			continue
		}
		index := iValue.(int)
		effected = append(effected, rule)
		ast.Policy = append(ast.Policy[:index], ast.Policy[index+1:]...)
		ast.PolicyMap.Delete(strings.Join(rule, DefaultSep))
		for i := index; i < len(ast.Policy); i++ {
			ast.PolicyMap.Store(strings.Join(ast.Policy[i], DefaultSep), i)
		}
	}
	return effected
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
func (model *Model) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, [][]string) {
	var tmp [][]string
	var effects [][]string
	res := false
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return ok, effects
	}
	ast.PolicyMap = new(sync.Map)

	for _, rule := range ast.Policy {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			effects = append(effects, rule)
		} else {
			tmp = append(tmp, rule)
			ast.PolicyMap.Store(strings.Join(rule, DefaultSep), len(tmp)-1)
		}
	}

	if len(tmp) != len(ast.Policy) {
		ast.Policy = tmp
		res = true
	}

	return res, effects
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
func (model *Model) GetValuesForFieldInPolicy(sec string, ptype string, fieldIndex int) []string {
	values := []string{}
	ast, ok := model.GetAstBySecPType(sec, ptype)
	if !ok {
		return values
	}
	for _, rule := range ast.Policy {
		values = append(values, rule[fieldIndex])
	}

	util.ArrayRemoveDuplicates(&values)

	return values
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
func (model *Model) GetValuesForFieldInPolicyAllTypes(sec string, fieldIndex int) []string {
	values := []string{}
	amap, ok := model.GetKey(sec)
	if !ok {
		return values
	}
	amap.Range(func(key, value interface{}) bool {
		values = append(values, model.GetValuesForFieldInPolicy(sec, key.(string), fieldIndex)...)
		return true
	})
	util.ArrayRemoveDuplicates(&values)

	return values
}

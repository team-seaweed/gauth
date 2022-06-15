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
	"container/list"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/team-seaweed/gauth/config"
	"github.com/team-seaweed/gauth/log"
	"github.com/team-seaweed/gauth/util"
)

// Model represents the whole access control model.
//type Model map[string]AssertionMap
type Model struct {
	sync.Map
}

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
//type AssertionMap map[string]*Assertion
type AssertionMap struct {
	sync.Map
}

const defaultDomain string = ""
const defaultSeparator = "::"

var sectionNameMap = map[string]string{
	"r": "request_definition",
	"p": "policy_definition",
	"g": "role_definition",
	"e": "policy_effect",
	"m": "matchers",
}

// Minimal required sections for a model to be valid
var requiredSections = []string{"r", "p", "e", "m"}

func loadAssertion(model *Model, cfg config.ConfigInterface, sec string, key string) bool {
	value := cfg.String(sectionNameMap[sec] + "::" + key)
	return model.AddDef(sec, key, value)
}

// AddDef adds an assertion to the model.
func (model *Model) AddDef(sec string, key string, value string) bool {
	if value == "" {
		return false
	}
	ast := new(Assertion)
	ast.Key = key
	ast.Value = value
	ast.PolicyMap = new(sync.Map)
	ast.setLogger(model.GetLogger())
	ast.initPriorityIndex()

	if sec == "r" || sec == "p" {
		ast.Tokens = strings.Split(ast.Value, ",")
		for i := range ast.Tokens {
			ast.Tokens[i] = key + "_" + strings.TrimSpace(ast.Tokens[i])
		}
	} else {
		ast.Value = util.RemoveComments(util.EscapeAssertion(ast.Value))
	}
	if sec == "m" && strings.Contains(ast.Value, "in") {
		ast.Value = strings.Replace(strings.Replace(ast.Value, "[", "(", -1), "]", ")", -1)
	}

	amap, ok := model.GetKey(sec)
	if !ok {
		amap = new(AssertionMap)
		model.Store(sec, amap)
	}
	amap.Store(key, ast)
	return true

}

func getKeySuffix(i int) string {
	if i == 1 {
		return ""
	}

	return strconv.Itoa(i)
}

func loadSection(model *Model, cfg config.ConfigInterface, sec string) {
	i := 1
	for {
		if !loadAssertion(model, cfg, sec, sec+getKeySuffix(i)) {
			break
		} else {
			i++
		}
	}
}

// SetLogger sets the model's logger.
func (model *Model) SetLogger(logger log.Logger) {
	model.Range(func(key1, value1 interface{}) bool {
		value1.(*AssertionMap).Range(func(key2, value2 interface{}) bool {
			value2.(*Assertion).logger = logger
			return true
		})
		return true
	})
	amap := new(AssertionMap)
	amap.Store("logger", &Assertion{logger: logger})
	model.Store("logger", amap)
}

// GetLogger returns the model's logger.
func (model *Model) GetLogger() log.Logger {
	amap, ok := model.GetKey("logger")
	if !ok {
		return nil
	}
	ast, ok := amap.GetKey("logger")
	if !ok {
		return nil
	}
	return ast.logger
}

// NewModel creates an empty model.
func NewModel() *Model {
	m := new(Model)
	m.SetLogger(&log.DefaultLogger{})

	return m
}

// NewModelFromFile creates a model from a .CONF file.
func NewModelFromFile(path string) (*Model, error) {
	m := NewModel()

	err := m.LoadModel(path)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// NewModelFromString creates a model from a string which contains model text.
func NewModelFromString(text string) (*Model, error) {
	m := NewModel()

	err := m.LoadModelFromText(text)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// LoadModel loads the model from model CONF file.
func (model *Model) LoadModel(path string) error {
	cfg, err := config.NewConfig(path)
	if err != nil {
		return err
	}

	return model.loadModelFromConfig(cfg)
}

// LoadModelFromText loads the model from the text.
func (model *Model) LoadModelFromText(text string) error {
	cfg, err := config.NewConfigFromText(text)
	if err != nil {
		return err
	}

	return model.loadModelFromConfig(cfg)
}

func (model *Model) loadModelFromConfig(cfg config.ConfigInterface) error {
	for s := range sectionNameMap {
		loadSection(model, cfg, s)
	}
	ms := make([]string, 0)
	for _, rs := range requiredSections {
		if !model.hasSection(rs) {
			ms = append(ms, sectionNameMap[rs])
		}
	}
	if len(ms) > 0 {
		return fmt.Errorf("missing required sections: %s", strings.Join(ms, ","))
	}
	return nil
}

func (model *Model) hasSection(sec string) bool {
	_, ok := model.Load(sec)
	return ok
}

// PrintModel prints the model to the log.
func (model *Model) PrintModel() {
	if !model.GetLogger().IsEnabled() {
		return
	}
	var modelInfo [][]string
	model.Range(func(k, v interface{}) bool {
		if k == "logger" {
			return true
		}
		v.(*AssertionMap).Range(func(key, value interface{}) bool {
			modelInfo = append(modelInfo, []string{k.(string), key.(string), value.(*Assertion).Value})
			return true
		})
		return true
	})
	model.GetLogger().LogModel(modelInfo)
}

func (model *Model) SortPoliciesBySubjectHierarchy() (err error) {
	east, ok := model.GetAstBySecPType("e", "e")
	if !ok {
		return errors.New("e sec not found")
	}
	if east.Value != "subjectPriority(p_eft) || deny" {
		return nil
	}
	subIndex := 0
	domainIndex := -1
	pmap, ok := model.GetKey("p")
	if !ok {
		return errors.New("p sec not found")
	}
	gast, ok := model.GetAstBySecPType("g", "g")
	if !ok {
		return errors.New("g sec not found")
	}

	pmap.Range(func(key, value interface{}) bool {
		ptype := key.(string)
		assertion := value.(*Assertion)
		for index, token := range assertion.Tokens {
			if token == fmt.Sprintf("%s_dom", ptype) {
				domainIndex = index
				break
			}
		}
		policies := assertion.Policy
		var subjectHierarchyMap map[string]int
		subjectHierarchyMap, err = getSubjectHierarchyMap(gast.Policy)
		if err != nil {
			return false
		}
		sort.SliceStable(policies, func(i, j int) bool {
			domain1, domain2 := defaultDomain, defaultDomain
			if domainIndex != -1 {
				domain1 = policies[i][domainIndex]
				domain2 = policies[j][domainIndex]
			}
			name1, name2 := getNameWithDomain(domain1, policies[i][subIndex]), getNameWithDomain(domain2, policies[j][subIndex])
			p1 := subjectHierarchyMap[name1]
			p2 := subjectHierarchyMap[name2]
			return p1 > p2
		})
		for i, policy := range assertion.Policy {
			assertion.PolicyMap.Store(strings.Join(policy, ","), i)
		}

		return true
	})
	return nil
}

func getSubjectHierarchyMap(policies [][]string) (map[string]int, error) {
	subjectHierarchyMap := make(map[string]int)
	// Tree structure of role
	policyMap := make(map[string][]string)
	for _, policy := range policies {
		if len(policy) < 2 {
			return nil, errors.New("policy g expect 2 more params")
		}
		domain := defaultDomain
		if len(policy) != 2 {
			domain = policy[2]
		}
		child := getNameWithDomain(domain, policy[0])
		parent := getNameWithDomain(domain, policy[1])
		policyMap[parent] = append(policyMap[parent], child)
		if _, ok := subjectHierarchyMap[child]; !ok {
			subjectHierarchyMap[child] = 0
		}
		if _, ok := subjectHierarchyMap[parent]; !ok {
			subjectHierarchyMap[parent] = 0
		}
		subjectHierarchyMap[child] = 1
	}
	// Use queues for levelOrder
	queue := list.New()
	for k, v := range subjectHierarchyMap {
		root := k
		if v != 0 {
			continue
		}
		lv := 0
		queue.PushBack(root)
		for queue.Len() != 0 {
			sz := queue.Len()
			for i := 0; i < sz; i++ {
				node := queue.Front()
				queue.Remove(node)
				nodeValue := node.Value.(string)
				subjectHierarchyMap[nodeValue] = lv
				if _, ok := policyMap[nodeValue]; ok {
					for _, child := range policyMap[nodeValue] {
						queue.PushBack(child)
					}
				}
			}
			lv++
		}
	}
	return subjectHierarchyMap, nil
}

func getNameWithDomain(domain string, name string) string {
	return domain + defaultSeparator + name
}

func (model *Model) SortPoliciesByPriority() error {
	pmap, ok := model.GetKey("p")
	if !ok {
		return errors.New("p sec not found")
	}
	var err error
	pmap.Range(func(key, value interface{}) bool {
		ptype := key.(string)
		assertion := value.(*Assertion)
		for index, token := range assertion.Tokens {
			if token == fmt.Sprintf("%s_priority", ptype) {
				assertion.priorityIndex = index
				break
			}
		}
		if assertion.priorityIndex == -1 {
			return true
		}
		policies := assertion.Policy
		sort.SliceStable(policies, func(i, j int) bool {
			var p1, p2 int
			p1, err = strconv.Atoi(policies[i][assertion.priorityIndex])
			if err != nil {
				return true
			}
			p2, err = strconv.Atoi(policies[j][assertion.priorityIndex])
			if err != nil {
				return true
			}
			return p1 < p2
		})
		for i, policy := range assertion.Policy {
			assertion.PolicyMap.Store(strings.Join(policy, ","), i)
		}
		return true
	})
	return nil
}

func (model *Model) ToText() string {
	tokenPatterns := make(map[string]string)

	pPattern, rPattern := regexp.MustCompile("^p_"), regexp.MustCompile("^r_")
	for _, ptype := range []string{"r", "p"} {
		ast, ok := model.GetAstBySecPType(ptype, ptype)
		if !ok {
			return ""
		}
		for _, token := range ast.Tokens {
			tokenPatterns[token] = rPattern.ReplaceAllString(pPattern.ReplaceAllString(token, "p."), "r.")
		}
	}
	east, ok := model.GetAstBySecPType("e", "e")
	if !ok {
		return ""
	}
	if strings.Contains(east.Value, "p_eft") {
		tokenPatterns["p_eft"] = "p.eft"
	}
	s := strings.Builder{}
	writeString := func(sec string) {
		amap, ok := model.GetKey(sec)
		if !ok {
			return
		}
		amap.Range(func(key1, value1 interface{}) bool {
			ast := value1.(*Assertion)
			value := ast.Value
			for tokenPattern, newToken := range tokenPatterns {
				value = strings.Replace(value, tokenPattern, newToken, -1)
			}
			s.WriteString(fmt.Sprintf("%s = %s\n", sec, value))
			return true
		})
	}
	s.WriteString("[request_definition]\n")
	writeString("r")
	s.WriteString("[policy_definition]\n")
	writeString("p")

	amap, ok := model.GetKey("g")
	if ok {
		s.WriteString("[role_definition]\n")
		amap.Range(func(key, value interface{}) bool {
			s.WriteString(fmt.Sprintf("%s = %s\n", key, value.(*Assertion).Value))
			return true
		})
	}
	s.WriteString("[policy_effect]\n")
	writeString("e")
	s.WriteString("[matchers]\n")
	writeString("m")
	return s.String()
}

func (model *Model) Copy() *Model {
	newModel := NewModel()
	model.Range(func(key, value interface{}) bool {
		newAstMap := new(AssertionMap)
		value.(*AssertionMap).Range(func(key, value interface{}) bool {
			newAstMap.Store(key.(string), value.(*Assertion).copy())
			return true
		})
		newModel.Store(key, newAstMap)
		return true
	})
	newModel.SetLogger(model.GetLogger())
	return newModel
}

func (model *Model) GetKey(sec string) (*AssertionMap, bool) {
	v, ok := model.Load(sec)
	if !ok {
		return nil, false
	}
	return v.(*AssertionMap), ok
}

func (model *Model) GetAstBySecPType(sec, ptype string) (*Assertion, bool) {
	v, ok1 := model.GetKey(sec)
	if !ok1 {
		return nil, false
	}
	return v.GetKey(ptype)
}

func (as *AssertionMap) GetKey(ptype string) (*Assertion, bool) {
	v, ok := as.Load(ptype)
	if !ok {
		return nil, false
	}
	return v.(*Assertion), ok
}

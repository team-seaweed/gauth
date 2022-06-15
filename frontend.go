// Copyright 2020 The casbin Authors. All Rights Reserved.
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

package gauth

import (
	"bytes"
	"encoding/json"
	"github.com/team-seaweed/gauth/model"
)

func CasbinJsGetPermissionForUser(e IEnforcer, user string) (string, error) {
	mod := e.GetModel()
	m := map[string]interface{}{}
	m["m"] = mod.ToText()
	policies := make([][]string, 0)
	amap, ok := mod.GetKey("p")
	if !ok {
		return "", nil
	}
	amap.Range(func(key1, value1 interface{}) bool {
		ptype := key1.(string)
		ast := value1.(*model.Assertion)
		for i := range ast.Policy {
			policies = append(policies, append([]string{ptype}, ast.Policy[i]...))
		}
		return true
	})
	m["p"] = policies
	result := bytes.NewBuffer([]byte{})
	encoder := json.NewEncoder(result)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(m)
	return result.String(), err
}

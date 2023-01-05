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

package gauth

// GetUsersForRoleInDomain gets the users that has a role inside a domain. Add by Gordon
func (e *Enforcer) GetUsersForRoleInDomain(name string, domain string) []string {
	ast, ok := e.model.GetAstBySecPType("g", "g")
	if !ok {
		return []string{}
	}
	res, _ := ast.RM.GetUsers(name, domain)
	return res
}

// GetRolesForUserInDomain gets the roles that a user has inside a domain.
func (e *Enforcer) GetRolesForUserInDomain(name string, domain string) []string {
	ast, ok := e.model.GetAstBySecPType("g", "g")
	if !ok {
		return []string{}
	}
	res, _ := ast.RM.GetRoles(name, domain)
	return res
}

// GetPermissionsForUserInDomain gets permissions for a user or role inside a domain.
func (e *Enforcer) GetPermissionsForUserInDomain(user string, domain string) [][]string {
	var res [][]string
	users, _ := e.GetRolesForUser(user, domain)
	users = append(users, user)
	for _, singleUser := range users {
		policy := e.GetFilteredPolicy(0, singleUser, domain)
		res = append(res, policy...)
	}
	return res
}

// AddRoleForUserInDomain adds a role for a user inside a domain.
// Returns false if the user already has the role (aka not affected).
func (e *Enforcer) AddRoleForUserInDomain(user string, role string, domain string) (bool, error) {
	return e.AddGroupingPolicy(user, role, domain)
}

// DeleteRoleForUserInDomain deletes a role for a user inside a domain.
// Returns false if the user does not have the role (aka not affected).
func (e *Enforcer) DeleteRoleForUserInDomain(user string, role string, domain string) (bool, error) {
	return e.RemoveGroupingPolicy(user, role, domain)
}

// DeleteRolesForUserInDomain deletes all roles for a user inside a domain.
// Returns false if the user does not have any roles (aka not affected).
func (e *Enforcer) DeleteRolesForUserInDomain(user string, domain string) (bool, error) {
	ast, ok := e.model.GetAstBySecPType("g", "g")
	if !ok {
		return ok, nil
	}
	roles, err := ast.RM.GetRoles(user, domain)
	if err != nil {
		return false, err
	}

	var rules [][]string
	for _, role := range roles {
		rules = append(rules, []string{user, role, domain})
	}

	return e.RemoveGroupingPolicies(rules)
}

// GetAllUsersByDomain would get all users associated with the domain.
func (e *Enforcer) GetAllUsersByDomain(domain string) []string {
	m := make(map[string]struct{})
	gast, ok := e.model.GetAstBySecPType("g", "g")
	if !ok {
		return []string{}
	}
	past, ok := e.model.GetAstBySecPType("p", "p")
	if !ok {
		return []string{}
	}
	users := make([]string, 0)
	index := e.getDomainIndex("p")

	getUser := func(index int, policies [][]string, domain string, m map[string]struct{}) []string {
		if len(policies) == 0 || len(policies[0]) <= index {
			return []string{}
		}
		res := make([]string, 0)
		for _, policy := range policies {
			if _, ok := m[policy[0]]; policy[index] == domain && !ok {
				res = append(res, policy[0])
				m[policy[0]] = struct{}{}
			}
		}
		return res
	}

	users = append(users, getUser(2, gast.Policy, domain, m)...)
	users = append(users, getUser(index, past.Policy, domain, m)...)
	return users
}

// DeleteAllUsersByDomain would delete all users associated with the domain.
func (e *Enforcer) DeleteAllUsersByDomain(domain string) (bool, error) {
	gast, ok := e.model.GetAstBySecPType("g", "g")
	if !ok {
		return ok, nil
	}
	past, ok := e.model.GetAstBySecPType("p", "p")
	if !ok {
		return ok, nil
	}
	index := e.getDomainIndex("p")

	getUser := func(index int, policies [][]string, domain string) [][]string {
		if len(policies) == 0 || len(policies[0]) <= index {
			return [][]string{}
		}
		res := make([][]string, 0)
		for _, policy := range policies {
			if policy[index] == domain {
				res = append(res, policy)
			}
		}
		return res
	}

	users := getUser(2, gast.Policy, domain)
	if _, err := e.RemoveGroupingPolicies(users); err != nil {
		return false, err
	}
	users = getUser(index, past.Policy, domain)
	if _, err := e.RemovePolicies(users); err != nil {
		return false, err
	}
	rm, ok := e.rmMap["g"]
	if ok {
		if !rm.DelDomain(domain) {
			return false, nil
		}
	}
	return true, nil
}

// DeleteDomains would delete all associated users and roles.
// It would delete all domains if parameter is not provided.
// 删除领域数据
func (e *Enforcer) DeleteDomains(domains ...string) (bool, error) {
	for _, domain := range domains {
		if _, err := e.DeleteAllUsersByDomain(domain); err != nil {
			return false, err
		}
	}
	return true, nil
}

// GetAllDomains would get all domains.
func (e *Enforcer) GetAllDomains() ([]string, error) {
	gast, ok := e.model.GetAstBySecPType("g", "g")
	if !ok {
		return []string{}, nil
	}
	return gast.RM.GetAllDomains()
}

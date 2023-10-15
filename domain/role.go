package domain

import (
	"strings"
)

type RolePermissions struct {
	rolePermissions map[string][]string
}

func NewRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomerById", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomerById", "NewTransaction"},
	}}
}

func (p RolePermissions) IsAuthorizedFor(role string, routeName string) bool {
	perms := p.rolePermissions[role]
	for _, r := range perms {
		if r == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false
}
